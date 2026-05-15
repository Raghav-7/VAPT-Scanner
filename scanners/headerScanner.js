const axios = require('axios');

const SECURITY_HEADERS = [
  {
    header: 'strict-transport-security',
    name: 'Strict-Transport-Security (HSTS)',
    description: 'Forces browsers to use HTTPS for all future requests.',
    severity: 'high',
    remediation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
  },
  {
    header: 'content-security-policy',
    name: 'Content-Security-Policy (CSP)',
    description: 'Prevents XSS, clickjacking, and other code injection attacks by defining approved content sources.',
    severity: 'high',
    remediation: "Add a restrictive CSP header. Example: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
  },
  {
    header: 'x-frame-options',
    name: 'X-Frame-Options',
    description: 'Prevents clickjacking by controlling whether the page can be embedded in frames.',
    severity: 'medium',
    remediation: 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
  },
  {
    header: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME-type sniffing attacks.',
    severity: 'medium',
    remediation: 'Add header: X-Content-Type-Options: nosniff'
  },
  {
    header: 'x-xss-protection',
    name: 'X-XSS-Protection',
    description: 'Legacy XSS filter for older browsers.',
    severity: 'low',
    remediation: 'Add header: X-XSS-Protection: 1; mode=block (or rely on CSP for modern browsers)'
  },
  {
    header: 'referrer-policy',
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information is sent with requests.',
    severity: 'low',
    remediation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
  },
  {
    header: 'permissions-policy',
    name: 'Permissions-Policy',
    description: 'Controls which browser features and APIs can be used.',
    severity: 'low',
    remediation: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()'
  },
  {
    header: 'x-permitted-cross-domain-policies',
    name: 'X-Permitted-Cross-Domain-Policies',
    description: 'Controls cross-domain policies for Flash and PDF viewers.',
    severity: 'low',
    remediation: 'Add header: X-Permitted-Cross-Domain-Policies: none'
  },
  {
    header: 'cross-origin-opener-policy',
    name: 'Cross-Origin-Opener-Policy (COOP)',
    description: 'Isolates the browsing context to prevent cross-origin attacks.',
    severity: 'low',
    remediation: 'Add header: Cross-Origin-Opener-Policy: same-origin'
  },
  {
    header: 'cross-origin-resource-policy',
    name: 'Cross-Origin-Resource-Policy (CORP)',
    description: 'Controls which origins can read the resource.',
    severity: 'low',
    remediation: 'Add header: Cross-Origin-Resource-Policy: same-origin'
  },
  {
    header: 'cross-origin-embedder-policy',
    name: 'Cross-Origin-Embedder-Policy (COEP)',
    description: 'Prevents loading cross-origin resources without explicit permission.',
    severity: 'low',
    remediation: 'Add header: Cross-Origin-Embedder-Policy: require-corp'
  }
];

const DISCLOSURE_HEADERS = [
  { header: 'server', name: 'Server Version Disclosure' },
  { header: 'x-powered-by', name: 'X-Powered-By Disclosure' },
  { header: 'x-aspnet-version', name: 'ASP.NET Version Disclosure' },
  { header: 'x-aspnetmvc-version', name: 'ASP.NET MVC Version Disclosure' },
  { header: 'x-runtime', name: 'Runtime Disclosure' },
  { header: 'x-generator', name: 'Generator Disclosure' },
];

async function scan(targetUrl) {
  const findings = [];

  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'UniversalVAPTScanner/1.0'
      }
    });

    const headers = response.headers;

    // Check for missing security headers
    for (const sh of SECURITY_HEADERS) {
      const value = headers[sh.header];
      if (!value) {
        findings.push({
          id: `header-missing-${sh.header}`,
          title: `Missing ${sh.name}`,
          category: 'Security Headers',
          severity: sh.severity,
          description: `The ${sh.name} header is not set. ${sh.description}`,
          evidence: `Response headers do not include '${sh.header}'`,
          remediation: sh.remediation,
          reference: 'https://owasp.org/www-project-secure-headers/'
        });
      } else {
        // Check for weak configurations
        if (sh.header === 'strict-transport-security') {
          const maxAge = parseInt((value.match(/max-age=(\d+)/) || [])[1] || '0');
          if (maxAge < 31536000) {
            findings.push({
              id: 'header-weak-hsts',
              title: 'Weak HSTS Configuration',
              category: 'Security Headers',
              severity: 'medium',
              description: `HSTS max-age is ${maxAge} seconds (less than 1 year recommended).`,
              evidence: `Strict-Transport-Security: ${value}`,
              remediation: 'Set max-age to at least 31536000 (1 year) and include includeSubDomains.',
              reference: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'
            });
          }
          if (!value.includes('includeSubDomains')) {
            findings.push({
              id: 'header-hsts-no-subdomains',
              title: 'HSTS Missing includeSubDomains',
              category: 'Security Headers',
              severity: 'low',
              description: 'HSTS does not include the includeSubDomains directive.',
              evidence: `Strict-Transport-Security: ${value}`,
              remediation: 'Add includeSubDomains to HSTS header.',
              reference: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'
            });
          }
        }

        if (sh.header === 'content-security-policy') {
          if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
            findings.push({
              id: 'header-weak-csp',
              title: 'Weak Content Security Policy',
              category: 'Security Headers',
              severity: 'medium',
              description: "CSP contains 'unsafe-inline' or 'unsafe-eval' which weakens XSS protection.",
              evidence: `Content-Security-Policy: ${value.substring(0, 200)}...`,
              remediation: "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonce or hash-based CSP instead.",
              reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
            });
          }
          if (value.includes('*')) {
            findings.push({
              id: 'header-csp-wildcard',
              title: 'CSP Contains Wildcard Sources',
              category: 'Security Headers',
              severity: 'medium',
              description: 'CSP uses wildcard (*) source which effectively disables the protection.',
              evidence: `Content-Security-Policy: ${value.substring(0, 200)}...`,
              remediation: 'Replace wildcard sources with specific domain allowlists.',
              reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
            });
          }
        }

        if (sh.header === 'x-frame-options') {
          if (value.toUpperCase() !== 'DENY' && value.toUpperCase() !== 'SAMEORIGIN') {
            findings.push({
              id: 'header-weak-xfo',
              title: 'Weak X-Frame-Options Configuration',
              category: 'Security Headers',
              severity: 'medium',
              description: `X-Frame-Options has an unexpected value: ${value}`,
              evidence: `X-Frame-Options: ${value}`,
              remediation: 'Set X-Frame-Options to DENY or SAMEORIGIN.',
              reference: 'https://owasp.org/www-community/attacks/Clickjacking'
            });
          }
        }
      }
    }

    // Check for information disclosure headers
    for (const dh of DISCLOSURE_HEADERS) {
      const value = headers[dh.header];
      if (value) {
        findings.push({
          id: `header-disclosure-${dh.header}`,
          title: dh.name,
          category: 'Security Headers',
          severity: 'info',
          description: `The ${dh.header} header reveals server technology information that could help attackers.`,
          evidence: `${dh.header}: ${value}`,
          remediation: `Remove or mask the '${dh.header}' header to prevent information disclosure.`,
          reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprinting_Web_Server'
        });
      }
    }

    // Check for CORS misconfiguration
    const corsOrigin = headers['access-control-allow-origin'];
    if (corsOrigin === '*') {
      findings.push({
        id: 'header-cors-wildcard',
        title: 'CORS Wildcard Origin Allowed',
        category: 'Security Headers',
        severity: 'medium',
        description: 'The server allows requests from any origin (Access-Control-Allow-Origin: *), which could enable cross-origin data theft.',
        evidence: `Access-Control-Allow-Origin: ${corsOrigin}`,
        remediation: 'Restrict CORS to specific trusted origins instead of using wildcard.',
        reference: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'
      });
    }

    const corsCredentials = headers['access-control-allow-credentials'];
    if (corsCredentials === 'true' && corsOrigin && corsOrigin !== '*') {
      findings.push({
        id: 'header-cors-credentials',
        title: 'CORS Allows Credentials with Reflected Origin',
        category: 'Security Headers',
        severity: 'high',
        description: 'CORS is configured to allow credentials with a reflected origin, which could enable authenticated cross-origin attacks.',
        evidence: `Access-Control-Allow-Origin: ${corsOrigin}, Access-Control-Allow-Credentials: true`,
        remediation: 'Validate the Origin header strictly and only reflect trusted origins when credentials are allowed.',
        reference: 'https://portswigger.net/web-security/cors'
      });
    }

    // Check Cache-Control for sensitive pages
    const cacheControl = headers['cache-control'];
    if (!cacheControl || (!cacheControl.includes('no-store') && !cacheControl.includes('no-cache'))) {
      findings.push({
        id: 'header-cache-control',
        title: 'Missing Cache-Control for Sensitive Data',
        category: 'Security Headers',
        severity: 'low',
        description: 'Responses may be cached by browsers or proxies, potentially exposing sensitive data.',
        evidence: cacheControl ? `Cache-Control: ${cacheControl}` : 'Cache-Control header not set',
        remediation: 'Add header: Cache-Control: no-store, no-cache, must-revalidate, private',
        reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses'
      });
    }

  } catch (err) {
    findings.push({
      id: 'header-scan-error',
      title: 'Header Scan Error',
      category: 'Security Headers',
      severity: 'info',
      description: `Could not complete header scan: ${err.message}`,
      evidence: err.code || err.message,
      remediation: 'Ensure the target URL is accessible.',
      reference: ''
    });
  }

  return findings;
}

module.exports = { scan };
