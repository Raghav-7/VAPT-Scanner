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
const axios = require('axios');
const https = require('https');

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
  { name: 'Framework-Specific', key: 'mendix', scanner: mendixScanner, icon: '🏗️' },
];

/**
 * Detect the technology stack of the target URL
 */
async function detectTechStack(targetUrl, headers = {}) {
  try {
    const response = await axios.get(targetUrl, {
      timeout: 10000,
      validateStatus: () => true,
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      headers: { ...headers }
    });
    const html = response.data.toString().toLowerCase();
    const respHeaders = response.headers;

    let techStack = 'Generic Web App';

    if (
      html.includes('mendix') || 
      html.includes('mxui.js') ||
      (respHeaders['x-mendix-cloud'] !== undefined) ||
      (respHeaders['set-cookie'] && respHeaders['set-cookie'].some(c => c.includes('XASID')))
    ) {
      techStack = 'Mendix';
    } else if (html.includes('_next/static') || html.includes('data-reactroot')) {
      techStack = 'React/Next.js';
    } else if (html.includes('ng-version') || html.includes('@angular')) {
      techStack = 'Angular';
    } else if (html.includes('data-v-') || html.includes('vue.js')) {
      techStack = 'Vue.js';
    } else if (respHeaders['x-powered-by'] && respHeaders['x-powered-by'].toLowerCase().includes('express')) {
      techStack = 'Node.js/Express';
    }

    return techStack;
  } catch (err) {
    return 'Unknown';
  }
}

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

  // Detect tech stack
  emit({
    type: 'tech_detection_started',
    data: { message: 'Detecting technology stack...' }
  });

  const techStack = await detectTechStack(targetUrl, scan.options?.headers || {});
  scan.techStack = techStack;

  emit({
    type: 'tech_detection_complete',
    data: { techStack }
  });

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
