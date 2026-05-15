const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

async function scan(targetUrl, options = {}) {
  const findings = [];

  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': 'MendixVAPTScanner/1.0' }
    });

    const html = typeof response.data === 'string' ? response.data : '';
    const headers = response.headers;

    // Phase 1: Check for CSRF tokens in forms
    if (html) {
      const $ = cheerio.load(html);
      const forms = $('form');

      if (forms.length > 0) {
        forms.each((idx, form) => {
          const action = $(form).attr('action') || '';
          const method = ($(form).attr('method') || 'GET').toUpperCase();

          if (method === 'POST') {
            // Look for CSRF token inputs
            const csrfInputs = $(form).find(
              'input[name*="csrf"], input[name*="token"], input[name*="_token"], ' +
              'input[name*="authenticity"], input[name*="__RequestVerificationToken"], ' +
              'input[name*="csrfmiddlewaretoken"], input[name*="mx-csrf-token"]'
            );

            if (csrfInputs.length === 0) {
              findings.push({
                id: `csrf-no-token-form-${idx}`,
                title: `POST Form Missing CSRF Token`,
                category: 'CSRF',
                severity: 'high',
                description: `A POST form (action: "${action || 'self'}") does not contain a CSRF token input. This may allow Cross-Site Request Forgery attacks.`,
                evidence: `Form #${idx + 1}, Action: ${action || 'self'}, Method: POST, No CSRF token field found`,
                remediation: 'Add a unique, unpredictable CSRF token to every state-changing form. Verify the token server-side.',
                reference: 'https://owasp.org/www-community/attacks/csrf'
              });
            } else {
              // Check if the token looks random enough
              csrfInputs.each((_, input) => {
                const tokenValue = $(input).attr('value') || '';
                if (tokenValue.length < 16) {
                  findings.push({
                    id: `csrf-weak-token-${idx}`,
                    title: 'Weak CSRF Token',
                    category: 'CSRF',
                    severity: 'medium',
                    description: `The CSRF token in form #${idx + 1} appears too short (${tokenValue.length} chars). Short tokens are easier to brute-force.`,
                    evidence: `Token name: ${$(input).attr('name')}, Length: ${tokenValue.length}`,
                    remediation: 'Use cryptographically random tokens of at least 32 characters.',
                    reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
                  });
                }
              });
            }
          }
        });

        // Check for forms with GET method that change state
        const getForms = $('form').filter((_, f) => {
          const m = ($(f).attr('method') || 'GET').toUpperCase();
          return m === 'GET';
        });

        if (getForms.length > 0) {
          const stateChangingKeywords = ['delete', 'remove', 'update', 'edit', 'create', 'add', 'save', 'submit'];
          getForms.each((idx, form) => {
            const action = ($(form).attr('action') || '').toLowerCase();
            const hasStateChanging = stateChangingKeywords.some(kw => action.includes(kw));
            if (hasStateChanging) {
              findings.push({
                id: `csrf-get-state-change-${idx}`,
                title: 'State-Changing Operation via GET',
                category: 'CSRF',
                severity: 'medium',
                description: `A form appears to perform a state-changing operation ("${action}") via GET method. GET requests should be idempotent.`,
                evidence: `Action: ${action}, Method: GET`,
                remediation: 'Use POST/PUT/DELETE for state-changing operations. Add CSRF tokens.',
                reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
              });
            }
          });
        }
      }
    }

    // Phase 2: Check SameSite cookie attribute
    const setCookies = headers['set-cookie'] || [];
    let hasSessionCookie = false;
    let sessionHasSameSite = false;

    for (const cookie of setCookies) {
      const lower = cookie.toLowerCase();
      if (lower.includes('session') || lower.includes('xassession') || lower.includes('jsession')) {
        hasSessionCookie = true;
        if (lower.includes('samesite=strict') || lower.includes('samesite=lax')) {
          sessionHasSameSite = true;
        }
      }
    }

    if (hasSessionCookie && !sessionHasSameSite) {
      findings.push({
        id: 'csrf-no-samesite-session',
        title: 'Session Cookie Missing SameSite Protection',
        category: 'CSRF',
        severity: 'medium',
        description: 'The session cookie does not have SameSite=Strict or SameSite=Lax attribute, which is a defense-in-depth measure against CSRF.',
        evidence: 'Session cookie found without SameSite attribute',
        remediation: 'Set SameSite=Lax (minimum) or SameSite=Strict on all session cookies.',
        reference: 'https://web.dev/samesite-cookies-explained/'
      });
    }

    // Phase 3: Test for CSRF token validation on API endpoints
    const mendixEndpoints = [
      { path: '/xas/', method: 'POST', name: 'Mendix XAS' },
      { path: '/api/', method: 'POST', name: 'Mendix API' },
      { path: '/rest/', method: 'POST', name: 'Mendix REST' },
    ];

    for (const ep of mendixEndpoints) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.pathname = ep.path;

        // Test without CSRF token
        const response = await axios({
          method: ep.method,
          url: testUrl.toString(),
          timeout: 8000,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'MendixVAPTScanner/1.0',
            'Content-Type': 'application/json',
            'Origin': 'https://attacker.example.com',
            'Referer': 'https://attacker.example.com/'
          },
          data: '{}'
        });

        // If the server accepts the request without CSRF validation
        if (response.status !== 403 && response.status !== 401 && response.status !== 400) {
          findings.push({
            id: `csrf-no-validation-${ep.name.replace(/\s+/g, '-')}`,
            title: `${ep.name} Endpoint Accepts Cross-Origin Requests`,
            category: 'CSRF',
            severity: 'high',
            description: `The ${ep.name} endpoint (${ep.path}) did not reject a request with a foreign Origin header. This suggests inadequate CSRF protection.`,
            evidence: `Endpoint: ${ep.path}, Origin: attacker.example.com, Response: ${response.status}`,
            remediation: 'Validate Origin/Referer headers. Require and verify CSRF tokens on all state-changing endpoints.',
            reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
          });
        }

        // Check if X-Csrf-Token header is required (Mendix pattern)
        const noCsrfResp = await axios({
          method: ep.method,
          url: testUrl.toString(),
          timeout: 8000,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'MendixVAPTScanner/1.0',
            'Content-Type': 'application/json'
          },
          data: '{}'
        });

        const withCsrfResp = await axios({
          method: ep.method,
          url: testUrl.toString(),
          timeout: 8000,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'MendixVAPTScanner/1.0',
            'Content-Type': 'application/json',
            'X-Csrf-Token': 'test-token-123'
          },
          data: '{}'
        });

        if (noCsrfResp.status === withCsrfResp.status && noCsrfResp.status < 400) {
          findings.push({
            id: `csrf-token-not-validated-${ep.name.replace(/\s+/g, '-')}`,
            title: `${ep.name} Does Not Validate CSRF Token`,
            category: 'CSRF',
            severity: 'medium',
            description: `The ${ep.name} endpoint accepts requests regardless of the X-Csrf-Token header value, suggesting the token is not validated.`,
            evidence: `Both requests (with and without token) returned status ${noCsrfResp.status}`,
            remediation: 'Implement and validate CSRF tokens on all state-changing endpoints.',
            reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
          });
        }

      } catch (err) {
        continue;
      }
    }

    // Phase 4: Check for custom header requirements (defense against CSRF)
    try {
      const apiUrl = new URL(targetUrl);
      apiUrl.pathname = '/xas/';

      // Simple request vs preflight-triggering request
      const simpleResp = await axios({
        method: 'POST',
        url: apiUrl.toString(),
        timeout: 8000,
        validateStatus: () => true,
        headers: {
          'Content-Type': 'text/plain' // Simple request, no preflight
        },
        data: '{}'
      });

      if (simpleResp.status < 400) {
        findings.push({
          id: 'csrf-simple-request-accepted',
          title: 'API Accepts Simple Cross-Origin Requests',
          category: 'CSRF',
          severity: 'medium',
          description: 'The API endpoint accepts POST requests with simple content types (text/plain), which do not trigger CORS preflight and are vulnerable to CSRF.',
          evidence: `POST /xas/ with Content-Type: text/plain returned ${simpleResp.status}`,
          remediation: 'Require Content-Type: application/json for API requests (triggers CORS preflight). Validate the Content-Type header server-side.',
          reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
        });
      }
    } catch (err) {
      // Skip
    }

  } catch (err) {
    findings.push({
      id: 'csrf-scan-error',
      title: 'CSRF Scan Error',
      category: 'CSRF',
      severity: 'info',
      description: `Could not complete CSRF scan: ${err.message}`,
      evidence: err.code || err.message,
      remediation: 'Ensure the target is accessible.',
      reference: ''
    });
  }

  return findings;
}

module.exports = { scan };
