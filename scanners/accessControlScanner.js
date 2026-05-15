const axios = require('axios');
const { URL } = require('url');

// Directory traversal payloads
const TRAVERSAL_PAYLOADS = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\win.ini',
  '....//....//....//etc/passwd',
  '..%2f..%2f..%2fetc%2fpasswd',
  '..%5c..%5c..%5cwindows%5cwin.ini',
  '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
  '..%252f..%252f..%252fetc%252fpasswd',
  '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
];

// Sensitive endpoints to test for access control
const SENSITIVE_PATHS = [
  { path: '/admin', name: 'Admin Panel', severity: 'critical' },
  { path: '/administrator', name: 'Administrator Panel', severity: 'critical' },
  { path: '/admin/', name: 'Admin Directory', severity: 'critical' },
  { path: '/console', name: 'Console', severity: 'critical' },
  { path: '/manager', name: 'Manager', severity: 'high' },
  { path: '/dashboard', name: 'Dashboard', severity: 'medium' },
  { path: '/api/admin', name: 'Admin API', severity: 'critical' },
  { path: '/api/v1/users', name: 'Users API', severity: 'high' },
  { path: '/api/v1/config', name: 'Config API', severity: 'high' },
  { path: '/actuator', name: 'Spring Actuator', severity: 'high' },
  { path: '/actuator/health', name: 'Health Endpoint', severity: 'medium' },
  { path: '/actuator/env', name: 'Environment Endpoint', severity: 'critical' },
  { path: '/actuator/beans', name: 'Beans Endpoint', severity: 'high' },
  { path: '/jolokia', name: 'Jolokia JMX', severity: 'critical' },
  { path: '/jmx', name: 'JMX Console', severity: 'critical' },
  { path: '/debug', name: 'Debug Endpoint', severity: 'high' },
  { path: '/trace', name: 'Trace Endpoint', severity: 'high' },
  { path: '/status', name: 'Status Page', severity: 'low' },
  { path: '/health', name: 'Health Check', severity: 'info' },
  { path: '/metrics', name: 'Metrics Endpoint', severity: 'medium' },
  { path: '/swagger-ui.html', name: 'Swagger UI', severity: 'medium' },
  { path: '/swagger-ui/', name: 'Swagger UI', severity: 'medium' },
  { path: '/api-docs', name: 'API Documentation', severity: 'medium' },
  { path: '/graphql', name: 'GraphQL Endpoint', severity: 'medium' },
  { path: '/graphiql', name: 'GraphiQL IDE', severity: 'high' },
  { path: '/phpmyadmin', name: 'phpMyAdmin', severity: 'critical' },
  { path: '/wp-admin', name: 'WordPress Admin', severity: 'critical' },
  { path: '/elmah.axd', name: 'ELMAH Error Log', severity: 'high' },

  // Mendix-specific
  { path: '/_mxadmin/', name: 'Mendix Admin', severity: 'critical' },
  { path: '/debugger/', name: 'Mendix Debugger', severity: 'critical' },
  { path: '/xas/', name: 'Mendix XAS Runtime', severity: 'medium' },
  { path: '/odata/', name: 'Mendix OData', severity: 'medium' },
  { path: '/rest/', name: 'Mendix REST', severity: 'medium' },
  { path: '/api-doc/', name: 'Mendix API Docs', severity: 'medium' },
  { path: '/api-doc/catalog', name: 'Mendix API Catalog', severity: 'medium' },
  { path: '/p/', name: 'Mendix Pages', severity: 'low' },
  { path: '/login.html', name: 'Login Page', severity: 'info' },
];

async function scan(targetUrl, options = {}) {
  const findings = [];
  const url = new URL(targetUrl);

  // Phase 1: Test for directory traversal
  const pathParams = ['file', 'path', 'dir', 'page', 'include', 'doc', 'document', 'template', 'folder', 'root'];
  const allParams = new Set(pathParams);
  for (const [key] of url.searchParams) {
    allParams.add(key);
  }

  for (const param of allParams) {
    for (const traversal of TRAVERSAL_PAYLOADS.slice(0, 4)) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, traversal);

        const response = await axios.get(testUrl.toString(), {
          timeout: 8000,
          validateStatus: () => true,
          headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
        });

        if (typeof response.data === 'string') {
          // Check for Unix passwd file content
          if (/root:.*:0:0:/i.test(response.data)) {
            findings.push({
              id: `access-traversal-${param}`,
              title: `Directory Traversal: ${param}`,
              category: 'Broken Access Control',
              severity: 'critical',
              description: `Parameter "${param}" is vulnerable to directory traversal. Server file /etc/passwd was successfully read.`,
              evidence: `Parameter: ${param}, Payload: ${traversal}, /etc/passwd content detected`,
              remediation: 'Validate and sanitize file paths. Use allowlists for file access. Never use user input directly in file paths.',
              reference: 'https://owasp.org/www-community/attacks/Path_Traversal'
            });
            break;
          }

          // Check for Windows win.ini content
          if (/\[fonts\]/i.test(response.data) || /\[extensions\]/i.test(response.data)) {
            findings.push({
              id: `access-traversal-win-${param}`,
              title: `Directory Traversal (Windows): ${param}`,
              category: 'Broken Access Control',
              severity: 'critical',
              description: `Parameter "${param}" is vulnerable to directory traversal. Windows file win.ini was successfully read.`,
              evidence: `Parameter: ${param}, Payload: ${traversal}, win.ini content detected`,
              remediation: 'Validate and sanitize file paths. Use allowlists for file access.',
              reference: 'https://owasp.org/www-community/attacks/Path_Traversal'
            });
            break;
          }
        }
      } catch (err) {
        continue;
      }
    }
    await sleep(100);
  }

  // Phase 2: Test for unauthorized access to sensitive endpoints
  for (const ep of SENSITIVE_PATHS) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.pathname = ep.path;

      const response = await axios.get(testUrl.toString(), {
        timeout: 8000,
        maxRedirects: 3,
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
      });

      if (response.status === 200) {
        const contentType = response.headers['content-type'] || '';
        const bodyLength = typeof response.data === 'string' ? response.data.length : 0;

        // Only report if there's actual content (not a generic 200 page)
        if (bodyLength > 100) {
          findings.push({
            id: `access-endpoint-${ep.path.replace(/\//g, '-')}`,
            title: `Sensitive Endpoint Accessible: ${ep.name}`,
            category: 'Broken Access Control',
            severity: ep.severity,
            description: `The endpoint "${ep.path}" (${ep.name}) is accessible without authentication. This may expose sensitive functionality.`,
            evidence: `Path: ${ep.path}, Status: 200, Content-Type: ${contentType}, Size: ${bodyLength} bytes`,
            remediation: `Restrict access to ${ep.name} endpoint. Implement authentication and authorization checks.`,
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
          });
        }
      } else if (response.status === 403) {
        findings.push({
          id: `access-endpoint-restricted-${ep.path.replace(/\//g, '-')}`,
          title: `Endpoint Exists (Restricted): ${ep.name}`,
          category: 'Broken Access Control',
          severity: 'info',
          description: `The endpoint "${ep.path}" exists but returns 403 Forbidden. It is properly restricted.`,
          evidence: `Path: ${ep.path}, Status: 403`,
          remediation: 'No immediate action required. Consider returning 404 instead of 403 to avoid information disclosure.',
          reference: ''
        });
      }
    } catch (err) {
      continue;
    }
  }

  // Phase 3: HTTP Method testing
  const methodsToTest = ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE'];

  for (const method of methodsToTest) {
    try {
      const response = await axios({
        method,
        url: targetUrl,
        timeout: 8000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
      });

      if (method === 'TRACE' && response.status === 200) {
        findings.push({
          id: 'access-trace-enabled',
          title: 'HTTP TRACE Method Enabled',
          category: 'Broken Access Control',
          severity: 'medium',
          description: 'The TRACE HTTP method is enabled. This can be exploited for Cross-Site Tracing (XST) attacks.',
          evidence: `TRACE ${targetUrl} -> ${response.status}`,
          remediation: 'Disable the TRACE HTTP method on the server.',
          reference: 'https://owasp.org/www-community/attacks/Cross_Site_Tracing'
        });
      }

      if (method === 'OPTIONS' && response.status === 200) {
        const allow = response.headers.allow || '';
        if (allow) {
          const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT'];
          const allowedDangerous = dangerousMethods.filter(m => allow.toUpperCase().includes(m));

          if (allowedDangerous.length > 0) {
            findings.push({
              id: 'access-dangerous-methods',
              title: 'Potentially Dangerous HTTP Methods Allowed',
              category: 'Broken Access Control',
              severity: 'medium',
              description: `The server allows potentially dangerous HTTP methods: ${allowedDangerous.join(', ')}`,
              evidence: `Allow: ${allow}`,
              remediation: 'Disable unnecessary HTTP methods. Only allow GET, POST, and HEAD unless specifically required.',
              reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'
            });
          }
        }
      }
    } catch (err) {
      continue;
    }
  }

  // Phase 4: IDOR testing indicators
  const numericParams = [];
  for (const [key, value] of url.searchParams) {
    if (/^\d+$/.test(value)) {
      numericParams.push({ key, value });
    }
  }

  for (const param of numericParams) {
    try {
      const originalValue = parseInt(param.value);
      const testValues = [originalValue + 1, originalValue - 1, originalValue + 100, 0, -1];
      let differentResponses = 0;

      for (const tv of testValues) {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param.key, tv.toString());

        const response = await axios.get(testUrl.toString(), {
          timeout: 8000,
          validateStatus: () => true,
          headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
        });

        if (response.status === 200) {
          differentResponses++;
        }
      }

      if (differentResponses > 2) {
        findings.push({
          id: `access-idor-${param.key}`,
          title: `Possible IDOR: ${param.key}`,
          category: 'Broken Access Control',
          severity: 'high',
          description: `Parameter "${param.key}" accepts different numeric IDs and returns valid responses. This may indicate an Insecure Direct Object Reference (IDOR) vulnerability.`,
          evidence: `Parameter: ${param.key}, Original: ${param.value}, ${differentResponses} alternative IDs returned valid responses`,
          remediation: 'Implement proper authorization checks. Verify that the authenticated user has permission to access the requested resource. Use indirect references.',
          reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'
        });
      }
    } catch (err) {
      continue;
    }
  }

  return findings;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { scan };
