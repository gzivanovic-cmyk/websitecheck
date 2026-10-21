// Websitecheck-overzicht bijwerken: nieuwe rapporten uit uit/<id>/ versleutelen naar data/ en (met --push) naar GitHub zetten.
// Versleuteling zoals het prospects-dashboard: AES-256-GCM, sleutel via PBKDF2-SHA256 (310000 iteraties) uit het wachtwoord in .password.
// In de repository komt NOOIT iets onversleuteld: uit/, private/, .password en .psi_key staan in .gitignore.
//
// Gebruik: node sync.js <map met uit/<id>/-mappen van de checkmachine> [--push]
//          node sync.js --verstuurd <website of id> [--datum JJJJ-MM-DD] [--push]   (rapport is naar de klant gemaild)
//   bijvoorbeeld: node sync.js ../websitecheck-motor/uit --push
const fs = require('fs'), path = require('path'), crypto = require('crypto'), { execSync } = require('child_process');
const HIER = __dirname, ITER = 310000;
// wachtwoord: uit de beveiligde opslag van de bot (WEBSITECHECK_PASSWORD) of uit .password
const pwf = path.join(HIER, '.password');
const pw = (process.env.WEBSITECHECK_PASSWORD || (fs.existsSync(pwf) ? fs.readFileSync(pwf, 'utf8') : '')).trim();
if (!pw) { console.error('Geen wachtwoord: zet WEBSITECHECK_PASSWORD of .password (vraag Goran)'); process.exit(1); }

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
const pos = process.argv.slice(2).filter((a, i, arr) => !a.startsWith('--') && !['--verstuurd', '--datum'].includes(arr[i - 1]));
const uit = path.resolve(pos[0] || path.join(HIER, 'uit'));
let nieuw = 0;
for (const id of (fs.existsSync(uit) ? fs.readdirSync(uit) : []).sort()) {
  const rf = path.join(uit, id, 'resultaat.json'), pf = path.join(uit, id, 'rapport.pdf');
  if (!fs.existsSync(rf) || !fs.existsSync(pf)) continue;
  const r = JSON.parse(fs.readFileSync(rf, 'utf8'));
  const s = r.samenvatting || {};
  if (!s.id) continue;  // alleen rapporten van verwerk.py (echte aanvragen), geen losse testrapporten
  const oud = lijst.find(c => c.id === id);
  if (oud && (!s.klantlink || oud.klantlink === s.klantlink)) continue;  // al bekend en niets nieuws (de klantlink komt na goedkeuren)
  fs.writeFileSync(path.join(dataDir, id + '.enc'), versleutel({ id, samenvatting: s, oordeel: r.oordeel, pdf: fs.readFileSync(pf).toString('base64') }));
  if (oud) { Object.assign(oud, s, { verstuurd: oud.verstuurd }); } else { lijst.push(s); nieuw++; }
}
// verstuurd registreren: node sync.js --verstuurd <website of id> [--datum JJJJ-MM-DD]
const vi = process.argv.indexOf('--verstuurd');
if (vi !== -1) {
  const wie = (process.argv[vi + 1] || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  const di = process.argv.indexOf('--datum'), datum = di !== -1 ? process.argv[di + 1] : new Date().toISOString().slice(0, 10);
  const kandidaten = lijst.filter(c => c.id === wie || (c.host || '').toLowerCase() === wie).sort((a, b) => (b.datum || '').localeCompare(a.datum || ''));
  if (!kandidaten.length) { console.error('Geen check gevonden voor ' + wie); process.exit(2); }
  kandidaten[0].verstuurd = datum;
  console.log(`Gemarkeerd als verstuurd: ${kandidaten[0].bedrijf || kandidaten[0].host} (${datum})`);
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
