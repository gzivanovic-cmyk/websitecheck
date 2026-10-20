// Websitecheck-overzicht bijwerken: nieuwe rapporten uit uit/<id>/ versleutelen naar data/ en (met --push) naar GitHub zetten.
// Versleuteling zoals het prospects-dashboard: AES-256-GCM, sleutel via PBKDF2-SHA256 (310000 iteraties) uit het wachtwoord in .password.
// In de repository komt NOOIT iets onversleuteld: uit/, private/, .password en .psi_key staan in .gitignore.
//
// Gebruik: node sync.js <map met uit/<id>/-mappen van de checkmachine> [--push]
//   bijvoorbeeld: node sync.js ../websitecheck-motor/uit --push
const fs = require('fs'), path = require('path'), crypto = require('crypto'), { execSync } = require('child_process');
const HIER = __dirname, ITER = 310000;
const pwf = path.join(HIER, '.password');
if (!fs.existsSync(pwf)) { console.error('.password ontbreekt: vraag Goran om het wachtwoord van het overzicht'); process.exit(1); }
const pw = fs.readFileSync(pwf, 'utf8').trim();

function versleutel(obj) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(pw, salt, ITER, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj))), c.final(), c.getAuthTag()]);
  return JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') });
}
function ontsleutel(tekst) {
  const d = JSON.parse(tekst), buf = Buffer.from(d.ct, 'base64');
  const key = crypto.pbkdf2Sync(pw, Buffer.from(d.salt, 'base64'), d.iter, 32, 'sha256');
  const dc = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(d.iv, 'base64'));
  dc.setAuthTag(buf.subarray(buf.length - 16));
  return JSON.parse(Buffer.concat([dc.update(buf.subarray(0, buf.length - 16)), dc.final()]).toString('utf8'));
}

const dataDir = path.join(HIER, 'data'); fs.mkdirSync(dataDir, { recursive: true });
const lijstF = path.join(dataDir, 'lijst.enc');
let lijst = [];
if (fs.existsSync(lijstF)) {
  try { lijst = ontsleutel(fs.readFileSync(lijstF, 'utf8')).checks || []; }
  catch (e) { console.error('Bestaande lijst niet te openen: klopt het wachtwoord in .password?'); process.exit(1); }
}
const bekend = new Set(lijst.map(c => c.id));
const uit = path.resolve(process.argv.slice(2).find(a => !a.startsWith('--')) || path.join(HIER, 'uit'));
let nieuw = 0;
for (const id of (fs.existsSync(uit) ? fs.readdirSync(uit) : []).sort()) {
  const rf = path.join(uit, id, 'resultaat.json'), pf = path.join(uit, id, 'rapport.pdf');
  if (bekend.has(id) || !fs.existsSync(rf) || !fs.existsSync(pf)) continue;
  const r = JSON.parse(fs.readFileSync(rf, 'utf8'));
  const s = r.samenvatting || {};
  if (!s.id) continue;  // alleen rapporten van verwerk.py (echte aanvragen), geen losse testrapporten
  fs.writeFileSync(path.join(dataDir, id + '.enc'), versleutel({ id, samenvatting: s, oordeel: r.oordeel, pdf: fs.readFileSync(pf).toString('base64') }));
  lijst.push(s); nieuw++;
}
lijst.sort((a, b) => (b.datum || '').localeCompare(a.datum || ''));
fs.writeFileSync(lijstF, versleutel({ bijgewerkt: new Date().toISOString(), checks: lijst }));
console.log(`Overzicht: ${lijst.length} checks, ${nieuw} nieuw.`);

if (process.argv.includes('--push')) {
  const sh = c => execSync(c, { cwd: HIER, stdio: 'inherit' });
  sh('git add data');
  const gestaged = execSync('git diff --cached --name-only', { cwd: HIER }).toString();
  if (/(^|\n)(uit|private)\/|\.password|\.psi_key/.test(gestaged)) { console.error('FOUT: geheime bestanden gestaged, gestopt'); process.exit(1); }
  if (!gestaged.trim()) { console.log('Geen wijzigingen'); process.exit(0); }
  sh(`git commit -qm "Websitechecks bijgewerkt ${new Date().toISOString().slice(0, 16).replace('T', ' ')}"`);
  sh('git push -q origin HEAD:main');
  console.log('Gepusht. Live: https://gzivanovic-cmyk.github.io/websitecheck/');
}
