const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

// Sensitive files and paths to check
const SENSITIVE_FILES = [
  { path: '/.env', name: '.env file', severity: 'critical' },
  { path: '/.env.local', name: '.env.local file', severity: 'critical' },
  { path: '/.env.production', name: '.env.production file', severity: 'critical' },
  { path: '/.git/config', name: 'Git Config', severity: 'critical' },
  { path: '/.git/HEAD', name: 'Git HEAD', severity: 'high' },
  { path: '/.gitignore', name: '.gitignore', severity: 'low' },
  { path: '/.svn/entries', name: 'SVN Entries', severity: 'high' },
  { path: '/.htaccess', name: '.htaccess', severity: 'medium' },
  { path: '/.htpasswd', name: '.htpasswd', severity: 'critical' },
  { path: '/web.config', name: 'web.config', severity: 'high' },
  { path: '/WEB-INF/web.xml', name: 'Java web.xml', severity: 'high' },
  { path: '/crossdomain.xml', name: 'crossdomain.xml', severity: 'medium' },
  { path: '/clientaccesspolicy.xml', name: 'clientaccesspolicy.xml', severity: 'medium' },
  { path: '/phpinfo.php', name: 'phpinfo', severity: 'high' },
  { path: '/info.php', name: 'PHP Info', severity: 'high' },
  { path: '/server-status', name: 'Server Status', severity: 'high' },
  { path: '/server-info', name: 'Server Info', severity: 'high' },
  { path: '/backup.sql', name: 'SQL Backup', severity: 'critical' },
  { path: '/backup.zip', name: 'Backup Archive', severity: 'critical' },
  { path: '/dump.sql', name: 'SQL Dump', severity: 'critical' },
  { path: '/config.json', name: 'Config JSON', severity: 'high' },
  { path: '/config.yaml', name: 'Config YAML', severity: 'high' },
  { path: '/config.yml', name: 'Config YML', severity: 'high' },
  { path: '/package.json', name: 'package.json', severity: 'low' },
  { path: '/composer.json', name: 'Composer JSON', severity: 'low' },

  // Mendix-specific
  { path: '/model-metadata.json', name: 'Mendix Model Metadata', severity: 'high' },
  { path: '/settings.json', name: 'Settings JSON', severity: 'high' },
  { path: '/m2ee.yaml', name: 'Mendix M2EE Config', severity: 'critical' },
  { path: '/m2ee.yml', name: 'Mendix M2EE Config', severity: 'critical' },
];

async function scan(targetUrl, options = {}) {
  const findings = [];
  const url = new URL(targetUrl);

  // Phase 1: Check for exposed sensitive files
  for (const file of SENSITIVE_FILES) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.pathname = file.path;

      const response = await axios.get(testUrl.toString(), {
        timeout: 8000,
        maxRedirects: 3,
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
      });

      if (response.status === 200) {
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        const contentType = response.headers['content-type'] || '';

        // Verify it's actual file content (not a custom 404 page)
        const isLikelyReal = (
          body.length > 10 &&
          !body.includes('404') &&
          !body.includes('not found') &&
          !body.includes('Page Not Found')
        );

        if (isLikelyReal) {
          // Check for sensitive data indicators
          const hasSensitiveData = /password|secret|key|token|credential|api_key|db_|database|mysql|postgres/i.test(body);

          findings.push({
            id: `misconfig-exposed-file-${file.path.replace(/\//g, '-')}`,
            title: `Exposed Sensitive File: ${file.name}`,
            category: 'Security Misconfiguration',
            severity: hasSensitiveData ? 'critical' : file.severity,
            description: `The file "${file.path}" is publicly accessible. ${hasSensitiveData ? 'ALERT: Sensitive data (credentials/keys) detected in file content!' : ''}`,
            evidence: `Path: ${file.path}, Status: 200, Size: ${body.length} bytes, Content-Type: ${contentType}${hasSensitiveData ? ', Contains sensitive data patterns' : ''}`,
            remediation: `Block public access to "${file.path}". Configure the web server to deny access to sensitive files and directories.`,
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
          });
        }
      }
    } catch (err) {
      continue;
    }
  }

  // Phase 2: Check for directory listing
  const dirsToCheck = ['/', '/css/', '/js/', '/images/', '/static/', '/assets/', '/uploads/', '/files/', '/media/', '/public/', '/resources/'];

  for (const dir of dirsToCheck) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.pathname = dir;

      const response = await axios.get(testUrl.toString(), {
        timeout: 8000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
      });

      if (response.status === 200 && typeof response.data === 'string') {
        const body = response.data.toLowerCase();
        if (
          body.includes('index of') ||
          body.includes('directory listing') ||
          body.includes('parent directory') ||
          body.includes('<title>directory') ||
          (body.includes('<pre>') && body.includes('href=') && body.match(/\d{4}-\d{2}-\d{2}/))
        ) {
          findings.push({
            id: `misconfig-dir-listing-${dir.replace(/\//g, '-')}`,
            title: `Directory Listing Enabled: ${dir}`,
            category: 'Security Misconfiguration',
            severity: 'medium',
            description: `Directory listing is enabled at "${dir}". This allows attackers to browse the directory structure and discover files.`,
            evidence: `Path: ${dir}, Directory listing indicators found in response`,
            remediation: 'Disable directory listing on the web server. Add index files or configure appropriate access controls.',
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
          });
        }
      }
    } catch (err) {
      continue;
    }
  }

  // Phase 3: Check for verbose error messages
  try {
    // Request a non-existent page
    const testUrl = new URL(targetUrl);
    testUrl.pathname = '/vapt-test-nonexistent-page-' + Date.now();

    const response = await axios.get(testUrl.toString(), {
      timeout: 8000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
    });

    if (typeof response.data === 'string') {
      const body = response.data;
      const errorIndicators = [
        { pattern: /stack\s*trace/i, name: 'Stack Trace' },
        { pattern: /exception/i, name: 'Exception Details' },
        { pattern: /at\s+[\w.]+\([^)]*:\d+\)/i, name: 'Stack Frame' },
        { pattern: /debug\s*mode/i, name: 'Debug Mode' },
        { pattern: /internal\s+server\s+error.*details/i, name: 'Detailed Error' },
        { pattern: /servlet|tomcat|jetty|jboss|weblogic/i, name: 'Server Technology' },
        { pattern: /com\.mendix\./i, name: 'Mendix Stack Trace' },
      ];

      for (const indicator of errorIndicators) {
        if (indicator.pattern.test(body)) {
          findings.push({
            id: `misconfig-verbose-error-${indicator.name.replace(/\s+/g, '-')}`,
            title: `Verbose Error Message: ${indicator.name}`,
            category: 'Security Misconfiguration',
            severity: 'medium',
            description: `Error pages reveal technical details (${indicator.name}). This information helps attackers understand the technology stack.`,
            evidence: `404 response contains ${indicator.name} patterns`,
            remediation: 'Configure custom error pages that do not reveal technical details. Disable debug mode in production.',
            reference: 'https://owasp.org/www-community/Improper_Error_Handling'
          });
        }
      }
    }
  } catch (err) {
    // Skip
  }

  // Phase 4: Check robots.txt for hidden paths
  try {
    const robotsUrl = new URL(targetUrl);
    robotsUrl.pathname = '/robots.txt';

    const response = await axios.get(robotsUrl.toString(), {
      timeout: 8000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
    });

    if (response.status === 200 && typeof response.data === 'string') {
      const body = response.data;

      // Extract disallowed paths
      const disallowedPaths = [];
      const lines = body.split('\n');
      for (const line of lines) {
        const match = line.match(/^Disallow:\s*(.+)/i);
        if (match) {
          disallowedPaths.push(match[1].trim());
        }
      }

      if (disallowedPaths.length > 0) {
        const sensitiveDisallowed = disallowedPaths.filter(p =>
          /admin|login|secret|private|internal|config|backup|db|api|debug|test|staging/i.test(p)
        );

        if (sensitiveDisallowed.length > 0) {
          findings.push({
            id: 'misconfig-robots-sensitive',
            title: 'Sensitive Paths in robots.txt',
            category: 'Security Misconfiguration',
            severity: 'low',
            description: `robots.txt reveals sensitive paths that may be interesting to attackers: ${sensitiveDisallowed.join(', ')}`,
            evidence: `Sensitive Disallowed paths: ${sensitiveDisallowed.join(', ')}`,
            remediation: 'Use proper authentication and authorization instead of relying on robots.txt for security. Consider if these paths need to be listed.',
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage'
          });
        }

        findings.push({
          id: 'misconfig-robots-found',
          title: 'robots.txt Found',
          category: 'Security Misconfiguration',
          severity: 'info',
          description: `robots.txt exists with ${disallowedPaths.length} disallowed path(s).`,
          evidence: `Disallowed paths: ${disallowedPaths.join(', ')}`,
          remediation: 'Review robots.txt entries. Ensure no sensitive paths are inadvertently disclosed.',
          reference: ''
        });
      }
    }
  } catch (err) {
    // Skip
  }

  // Phase 5: Check for debug/development mode indicators
  try {
    const response = await axios.get(targetUrl, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
    });

    if (typeof response.data === 'string') {
      const body = response.data;
      const debugPatterns = [
        { pattern: /debug\s*=\s*true/i, name: 'Debug Mode Enabled' },
        { pattern: /console\.(log|debug|info|warn|error)/g, name: 'Console Logging' },
        { pattern: /sourceMap/i, name: 'Source Maps' },
        { pattern: /<!--.*TODO/i, name: 'TODO Comments in HTML' },
        { pattern: /<!--.*HACK/i, name: 'HACK Comments in HTML' },
        { pattern: /<!--.*FIXME/i, name: 'FIXME Comments in HTML' },
        { pattern: /<!--.*password/i, name: 'Password in HTML Comments' },
        { pattern: /<!--.*secret/i, name: 'Secret in HTML Comments' },
      ];

      for (const dp of debugPatterns) {
        if (dp.pattern.test(body)) {
          findings.push({
            id: `misconfig-debug-${dp.name.replace(/\s+/g, '-')}`,
            title: `Development Artifact: ${dp.name}`,
            category: 'Security Misconfiguration',
            severity: dp.name.includes('Password') || dp.name.includes('Secret') ? 'high' : 'low',
            description: `Found "${dp.name}" in the page source. Development artifacts should be removed from production.`,
            evidence: `Pattern: ${dp.name} found in response`,
            remediation: 'Remove debug settings, console logs, comments with sensitive info, and source maps from production builds.',
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces'
          });
        }
      }
    }

    // Check response headers for debug indicators
    const headers = response.headers;
    if (headers['x-debug-token'] || headers['x-debug-token-link']) {
      findings.push({
        id: 'misconfig-debug-headers',
        title: 'Debug Headers Present',
        category: 'Security Misconfiguration',
        severity: 'medium',
        description: 'Debug-related headers (X-Debug-Token) are present in the response. This indicates the application is running in debug mode.',
        evidence: `X-Debug-Token: ${headers['x-debug-token'] || 'N/A'}`,
        remediation: 'Disable debug mode in production. Remove debug-related middleware.',
        reference: ''
      });
    }
  } catch (err) {
    // Skip
  }

  // Phase 6: Check for CORS misconfiguration (detailed)
  try {
    const response = await axios.get(targetUrl, {
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'UniversalVAPTScanner/1.0',
        'Origin': 'https://evil-attacker.com'
      }
    });

    const corsOrigin = response.headers['access-control-allow-origin'];
    if (corsOrigin === 'https://evil-attacker.com') {
      findings.push({
        id: 'misconfig-cors-origin-reflected',
        title: 'CORS Origin Reflection',
        category: 'Security Misconfiguration',
        severity: 'high',
        description: 'The server reflects the Origin header in Access-Control-Allow-Origin, allowing any website to make authenticated cross-origin requests.',
        evidence: `Origin: evil-attacker.com reflected in ACAO header`,
        remediation: 'Implement a strict allowlist of trusted origins. Do not reflect the Origin header.',
        reference: 'https://portswigger.net/web-security/cors'
      });
    }

    // Test null origin
    const nullResp = await axios.get(targetUrl, {
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'UniversalVAPTScanner/1.0',
        'Origin': 'null'
      }
    });

    if (nullResp.headers['access-control-allow-origin'] === 'null') {
      findings.push({
        id: 'misconfig-cors-null-origin',
        title: 'CORS Allows Null Origin',
        category: 'Security Misconfiguration',
        severity: 'high',
        description: 'The server allows the null Origin, which can be exploited via sandboxed iframes and data URIs.',
        evidence: 'Access-Control-Allow-Origin: null',
        remediation: 'Do not allow the null Origin. Implement strict origin validation.',
        reference: 'https://portswigger.net/web-security/cors'
      });
    }
  } catch (err) {
    // Skip
  }

  return findings;
}

module.exports = { scan };
