const fs = require('fs'); 
const path = require('path'); 
const dir = path.join(__dirname, 'scanners'); 
const files = fs.readdirSync(dir).filter(f => f.endsWith('.js') && f !== 'index.js'); 
files.forEach(f => { 
  let content = fs.readFileSync(path.join(dir, f), 'utf8'); 
  content = content.replace(/headers:\s*\{([^}]*)\}/g, (m, p1) => 'headers: { ' + p1.trim() + ', ...(options.headers || {}) }'); 
  fs.writeFileSync(path.join(dir, f), content); 
});
