// Websitecheck-overzicht bijwerken: nieuwe rapporten uit uit/<id>/ versleutelen naar data/ en (met --push) naar GitHub zetten.
// Versleuteling zoals het prospects-dashboard: AES-256-GCM, sleutel via PBKDF2-SHA256 (310000 iteraties) uit het wachtwoord in .password.
// In de repository komt NOOIT iets onversleuteld: uit/, private/, .password, .password-ais en .psi_key staan in .gitignore.
// Daarnaast een aparte set voor het AIS-dashboard (rapport.ais-groep.nl/dashboard/): data-ais/ met alleen de AIS-checks, versleuteld met een eigen
// wachtwoord (WEBSITECHECK_AIS_PASSWORD of .password-ais). GO 4IT-checks komen daar nooit in. Zonder AIS-wachtwoord slaat sync.js dit over.
//
// Gebruik: node sync.js <map met uit/<id>/-mappen van de checkmachine> [--push]
//          node sync.js --verstuurd <website of id> [--datum JJJJ-MM-DD] [--push]   (rapport is naar de klant gemaild)
//          node sync.js <uit-map> --wissen <id> [--push]   (Goran veegde hem weg in zijn overzicht; komt daarna niet meer terug)
//   bijvoorbeeld: node sync.js ../websitecheck-motor/uit --push
const fs = require('fs'), path = require('path'), crypto = require('crypto'), { execSync } = require('child_process');
const HIER = __dirname, ITER = 310000;
// wachtwoord: uit de beveiligde opslag van de bot (WEBSITECHECK_PASSWORD) of uit .password
const pwf = path.join(HIER, '.password');
const pw = (process.env.WEBSITECHECK_PASSWORD || (fs.existsSync(pwf) ? fs.readFileSync(pwf, 'utf8') : '')).trim();
if (!pw) { console.error('Geen wachtwoord: zet WEBSITECHECK_PASSWORD of .password (vraag Goran)'); process.exit(1); }
const pwAisF = path.join(HIER, '.password-ais');
const pwAis = (process.env.WEBSITECHECK_AIS_PASSWORD || (fs.existsSync(pwAisF) ? fs.readFileSync(pwAisF, 'utf8') : '')).trim();
if (pwAis && pwAis === pw) { console.error('Het AIS-wachtwoord moet anders zijn dan dat van het overzicht'); process.exit(1); }

function versleutel(obj, wachtwoord = pw) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(wachtwoord, salt, ITER, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj))), c.final(), c.getAuthTag()]);
  return JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') });
}
function ontsleutel(tekst, wachtwoord = pw) {
  const d = JSON.parse(tekst), buf = Buffer.from(d.ct, 'base64');
  const key = crypto.pbkdf2Sync(wachtwoord, Buffer.from(d.salt, 'base64'), d.iter, 32, 'sha256');
  const dc = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(d.iv, 'base64'));
  dc.setAuthTag(buf.subarray(buf.length - 16));
  return JSON.parse(Buffer.concat([dc.update(buf.subarray(0, buf.length - 16)), dc.final()]).toString('utf8'));
}

const dataDir = path.join(HIER, 'data'); fs.mkdirSync(dataDir, { recursive: true });
const lijstF = path.join(dataDir, 'lijst.enc');
let lijst = [], gewist = [];   // gewist: ids die Goran uit zijn overzicht heeft gehaald (die zet sync.js niet meer terug)
if (fs.existsSync(lijstF)) {
  try { const l = ontsleutel(fs.readFileSync(lijstF, 'utf8')); lijst = l.checks || []; gewist = l.gewist || []; }
  catch (e) { console.error('Bestaande lijst niet te openen: klopt het wachtwoord in .password?'); process.exit(1); }
}
const bekend = new Set(lijst.map(c => c.id));
const pos = process.argv.slice(2).filter((a, i, arr) => !a.startsWith('--') && !['--verstuurd', '--datum', '--wissen'].includes(arr[i - 1]));
const uit = path.resolve(pos[0] || path.join(HIER, 'uit'));
let nieuw = 0;
const gewijzigd = new Set();   // ids waarvan data/<id>.enc deze keer opnieuw is geschreven
for (const id of (fs.existsSync(uit) ? fs.readdirSync(uit) : []).sort()) {
  const rf = path.join(uit, id, 'resultaat.json'), pf = path.join(uit, id, 'rapport.pdf');
  if (!fs.existsSync(rf)) continue;
  const r = JSON.parse(fs.readFileSync(rf, 'utf8'));
  const s = r.samenvatting || {};
  if (!fs.existsSync(pf) && !s.mislukt) continue;   // zonder rapport alleen een mislukte check (met de reden)
  if (!s.id) continue;  // alleen rapporten van verwerk.py (echte aanvragen), geen losse testrapporten
  if (gewist.includes(id)) continue;  // door Goran uit het overzicht gehaald
  const oud = lijst.find(c => c.id === id);
  if (oud && (oud.klantlink || '') === (s.klantlink || '') && JSON.stringify(oud.meldingen || []) === JSON.stringify(s.meldingen || [])) continue;  // al bekend en niets nieuws
  fs.writeFileSync(path.join(dataDir, id + '.enc'), versleutel({ id, samenvatting: s, oordeel: r.oordeel, pdf: fs.existsSync(pf) ? fs.readFileSync(pf).toString('base64') : null }));
  gewijzigd.add(id);
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
// uit het overzicht halen: node sync.js <uit-map> --wissen <id>. Het rapport blijft in uit/<id>/ staan.
const wi = process.argv.indexOf('--wissen');
let wisAis = '';
if (wi !== -1) {
  const id = process.argv[wi + 1] || '';
  if (!/^\d{4}-\d\d-\d\d-\d{4}-[a-z0-9-]{1,80}$/.test(id)) { console.error('Geen geldig id: ' + id); process.exit(2); }
  const voor = lijst.length;
  if (lijst.some(c => c.id === id && c.bron === 'ais')) wisAis = id;
  lijst = lijst.filter(c => c.id !== id);
  if (!gewist.includes(id)) gewist.push(id);
  const f = path.join(dataDir, id + '.enc'); if (fs.existsSync(f)) fs.unlinkSync(f);
  console.log(voor > lijst.length ? `Uit het overzicht gehaald: ${id}` : `Stond al niet (meer) in het overzicht: ${id}`);
}
lijst.sort((a, b) => (b.datum || '').localeCompare(a.datum || ''));
fs.writeFileSync(lijstF, versleutel({ bijgewerkt: new Date().toISOString(), checks: lijst, gewist }));
console.log(`Overzicht: ${lijst.length} checks, ${nieuw} nieuw.`);

// AIS-dashboard: dezelfde opbouw, maar alleen bron 'ais' en met het AIS-wachtwoord
if (pwAis) {
  const aisDir = path.join(HIER, 'data-ais'), aisLijstF = path.join(aisDir, 'lijst.enc');
  fs.mkdirSync(aisDir, { recursive: true });
  let gewistAis = [], opnieuw = false;
  if (fs.existsSync(aisLijstF)) {
    try { gewistAis = ontsleutel(fs.readFileSync(aisLijstF, 'utf8'), pwAis).gewist || []; }
    catch (e) { opnieuw = true; console.log('AIS-lijst niet te openen met het AIS-wachtwoord: de AIS-set wordt opnieuw opgebouwd.'); }
  }
  if (wisAis && !gewistAis.includes(wisAis)) gewistAis.push(wisAis);
  const ais = lijst.filter(c => c.bron === 'ais'), ids = new Set(ais.map(c => c.id));
  for (const c of ais) {
    const f = path.join(aisDir, c.id + '.enc'), bronF = path.join(dataDir, c.id + '.enc');
    if (fs.existsSync(f) && !opnieuw && !gewijzigd.has(c.id)) continue;
    if (fs.existsSync(bronF)) fs.writeFileSync(f, versleutel(ontsleutel(fs.readFileSync(bronF, 'utf8')), pwAis));
  }
  for (const f of fs.readdirSync(aisDir)) {
    if (f.endsWith('.enc') && f !== 'lijst.enc' && !ids.has(f.slice(0, -4))) fs.unlinkSync(path.join(aisDir, f));
  }
  fs.writeFileSync(aisLijstF, versleutel({ bijgewerkt: new Date().toISOString(), checks: ais, gewist: gewistAis }, pwAis));
  console.log(`AIS-dashboard: ${ais.length} checks.`);
}

if (process.argv.includes('--push')) {
  const sh = c => execSync(c, { cwd: HIER, stdio: 'inherit' });
  sh('git add -A data' + (fs.existsSync(path.join(HIER, 'data-ais')) ? ' data-ais' : ''));
  const gestaged = execSync('git diff --cached --name-only', { cwd: HIER }).toString();
  if (/(^|\n)(uit|private)\/|\.password|\.psi_key/.test(gestaged)) { console.error('FOUT: geheime bestanden gestaged, gestopt'); process.exit(1); }
  if (!gestaged.trim()) { console.log('Geen wijzigingen'); process.exit(0); }
  sh(`git commit -qm "Websitechecks bijgewerkt ${new Date().toISOString().slice(0, 16).replace('T', ' ')}"`);
  sh('git push -q origin HEAD:main');
  console.log('Gepusht. Het overzicht: https://www.go4itstudio.com/overzicht');
}
