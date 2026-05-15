const headerScanner = require('./headerScanner');
const sslScanner = require('./sslScanner');
const cookieScanner = require('./cookieScanner');
const xssScanner = require('./xssScanner');
const injectionScanner = require('./injectionScanner');
const ssrfScanner = require('./ssrfScanner');
const csrfScanner = require('./csrfScanner');
const accessControlScanner = require('./accessControlScanner');
const misconfigScanner = require('./misconfigScanner');
const cryptoScanner = require('./cryptoScanner');
const mendixScanner = require('./mendixScanner');

const SCANNER_MODULES = [
  { name: 'Security Headers', key: 'headers', scanner: headerScanner, icon: '🛡️' },
  { name: 'SSL/TLS Analysis', key: 'ssl', scanner: sslScanner, icon: '🔒' },
  { name: 'Cookie Security', key: 'cookies', scanner: cookieScanner, icon: '🍪' },
  { name: 'XSS Detection', key: 'xss', scanner: xssScanner, icon: '💉' },
  { name: 'Injection Testing', key: 'injection', scanner: injectionScanner, icon: '🗃️' },
  { name: 'SSRF Detection', key: 'ssrf', scanner: ssrfScanner, icon: '🌐' },
  { name: 'CSRF Analysis', key: 'csrf', scanner: csrfScanner, icon: '🔄' },
  { name: 'Access Control', key: 'access', scanner: accessControlScanner, icon: '🚪' },
  { name: 'Security Misconfig', key: 'misconfig', scanner: misconfigScanner, icon: '⚙️' },
  { name: 'Cryptographic Failures', key: 'crypto', scanner: cryptoScanner, icon: '🔐' },
  { name: 'Mendix-Specific', key: 'mendix', scanner: mendixScanner, icon: '🏗️' },
];

/**
 * Run a full VAPT scan against the target URL
 * @param {Object} scan - Scan configuration object
 * @param {Function} emit - Callback to emit events (type, data)
 */
async function runFullScan(scan, emit) {
  const { targetUrl, modules: selectedModules } = scan;

  // Determine which modules to run
  let modulesToRun = SCANNER_MODULES;
  if (selectedModules && selectedModules !== 'all' && Array.isArray(selectedModules)) {
    modulesToRun = SCANNER_MODULES.filter(m => selectedModules.includes(m.key));
  }

  const totalModules = modulesToRun.length;
  let completedModules = 0;

  emit({
    type: 'scan_started',
    data: {
      totalModules,
      modules: modulesToRun.map(m => ({ name: m.name, key: m.key, icon: m.icon }))
    }
  });

  for (const mod of modulesToRun) {
    emit({
      type: 'module_started',
      data: { module: mod.name, key: mod.key, icon: mod.icon }
    });

    try {
      const findings = await mod.scanner.scan(targetUrl, scan.options || {});

      completedModules++;
      const percent = Math.round((completedModules / totalModules) * 100);

      emit({
        type: 'module_complete',
        data: {
          module: mod.name,
          key: mod.key,
          icon: mod.icon,
          findings: findings || [],
          findingsCount: (findings || []).length
        }
      });

      emit({
        type: 'progress',
        data: { percent, completedModules, totalModules }
      });
    } catch (err) {
      completedModules++;
      const percent = Math.round((completedModules / totalModules) * 100);

      emit({
        type: 'module_error',
        data: {
          module: mod.name,
          key: mod.key,
          error: err.message
        }
      });

      emit({
        type: 'progress',
        data: { percent, completedModules, totalModules }
      });
    }
  }
}

module.exports = { runFullScan, SCANNER_MODULES };
