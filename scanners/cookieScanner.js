const axios = require('axios');

async function scan(targetUrl) {
  const findings = [];

  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
    });

    const setCookieHeaders = response.headers['set-cookie'] || [];

    if (setCookieHeaders.length === 0) {
      findings.push({
        id: 'cookie-none-found',
        title: 'No Cookies Set',
        category: 'Cookie Security',
        severity: 'info',
        description: 'No cookies were set in the initial response. Cookies may be set after authentication.',
        evidence: 'No Set-Cookie headers found',
        remediation: 'No action required at this stage. Re-scan after authentication if applicable.',
        reference: ''
      });
      return findings;
    }

    for (let i = 0; i < setCookieHeaders.length; i++) {
      const cookieStr = setCookieHeaders[i];
      const parsed = parseCookie(cookieStr);

      // Check for Secure flag
      if (!parsed.secure) {
        findings.push({
          id: `cookie-no-secure-${i}`,
          title: `Cookie Missing Secure Flag: ${parsed.name}`,
          category: 'Cookie Security',
          severity: 'high',
          description: `The cookie "${parsed.name}" does not have the Secure flag, meaning it can be transmitted over unencrypted HTTP connections.`,
          evidence: `Set-Cookie: ${cookieStr.substring(0, 150)}`,
          remediation: 'Add the Secure flag to all cookies containing sensitive data.',
          reference: 'https://owasp.org/www-community/controls/SecureCookieAttribute'
        });
      }

      // Check for HttpOnly flag
      if (!parsed.httpOnly) {
        const severity = isSessionCookie(parsed.name) ? 'high' : 'medium';
        findings.push({
          id: `cookie-no-httponly-${i}`,
          title: `Cookie Missing HttpOnly Flag: ${parsed.name}`,
          category: 'Cookie Security',
          severity,
          description: `The cookie "${parsed.name}" does not have the HttpOnly flag, making it accessible via JavaScript (vulnerable to XSS cookie theft).`,
          evidence: `Set-Cookie: ${cookieStr.substring(0, 150)}`,
          remediation: 'Add the HttpOnly flag to prevent client-side JavaScript access.',
          reference: 'https://owasp.org/www-community/HttpOnly'
        });
      }

      // Check for SameSite attribute
      if (!parsed.sameSite) {
        findings.push({
          id: `cookie-no-samesite-${i}`,
          title: `Cookie Missing SameSite Attribute: ${parsed.name}`,
          category: 'Cookie Security',
          severity: 'medium',
          description: `The cookie "${parsed.name}" does not have the SameSite attribute, which helps prevent CSRF attacks.`,
          evidence: `Set-Cookie: ${cookieStr.substring(0, 150)}`,
          remediation: 'Add SameSite=Strict or SameSite=Lax to the cookie.',
          reference: 'https://owasp.org/www-community/SameSite'
        });
      } else if (parsed.sameSite.toLowerCase() === 'none' && !parsed.secure) {
        findings.push({
          id: `cookie-samesite-none-insecure-${i}`,
          title: `SameSite=None Without Secure: ${parsed.name}`,
          category: 'Cookie Security',
          severity: 'high',
          description: `Cookie "${parsed.name}" has SameSite=None but lacks the Secure flag. Modern browsers will reject this cookie.`,
          evidence: `Set-Cookie: ${cookieStr.substring(0, 150)}`,
          remediation: 'When using SameSite=None, the Secure flag must also be set.',
          reference: 'https://web.dev/samesite-cookies-explained/'
        });
      }

      // Check for overly broad domain
      if (parsed.domain) {
        const domainParts = parsed.domain.replace(/^\./, '').split('.');
        if (domainParts.length <= 2) {
          findings.push({
            id: `cookie-broad-domain-${i}`,
            title: `Overly Broad Cookie Domain: ${parsed.name}`,
            category: 'Cookie Security',
            severity: 'low',
            description: `Cookie "${parsed.name}" is scoped to "${parsed.domain}", which may expose it to subdomains.`,
            evidence: `Domain: ${parsed.domain}`,
            remediation: 'Restrict cookie domain to the most specific subdomain needed.',
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes'
          });
        }
      }

      // Check for overly broad path
      if (parsed.path === '/' || !parsed.path) {
        // This is common but worth noting for session cookies
        if (isSessionCookie(parsed.name)) {
          findings.push({
            id: `cookie-broad-path-${i}`,
            title: `Session Cookie with Broad Path: ${parsed.name}`,
            category: 'Cookie Security',
            severity: 'info',
            description: `Session cookie "${parsed.name}" is scoped to path "/". Consider restricting if the app serves multiple paths.`,
            evidence: `Path: ${parsed.path || '/'}`,
            remediation: 'Consider restricting cookie path to the application root.',
            reference: ''
          });
        }
      }

      // Check for potential sensitive data in cookie value
      const sensitivePatterns = [
        { pattern: /password/i, name: 'password' },
        { pattern: /credit.?card/i, name: 'credit card' },
        { pattern: /ssn/i, name: 'SSN' },
        { pattern: /token/i, name: 'token' },
        { pattern: /api.?key/i, name: 'API key' },
      ];

      for (const sp of sensitivePatterns) {
        if (sp.pattern.test(parsed.name) && parsed.value && parsed.value.length > 5) {
          findings.push({
            id: `cookie-sensitive-data-${i}-${sp.name}`,
            title: `Potential Sensitive Data in Cookie: ${parsed.name}`,
            category: 'Cookie Security',
            severity: 'medium',
            description: `Cookie name "${parsed.name}" suggests it may contain ${sp.name} data.`,
            evidence: `Cookie: ${parsed.name}=${parsed.value.substring(0, 20)}...`,
            remediation: 'Avoid storing sensitive data in cookies. Use server-side sessions instead.',
            reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes'
          });
        }
      }

      // Mendix-specific: Check XASSESSIONID
      if (parsed.name === 'XASSESSIONID' || parsed.name === 'JSESSIONID') {
        if (!parsed.httpOnly || !parsed.secure) {
          findings.push({
            id: `cookie-mendix-session-insecure-${i}`,
            title: `Mendix Session Cookie Insecure: ${parsed.name}`,
            category: 'Cookie Security',
            severity: 'high',
            description: `The Mendix session cookie "${parsed.name}" is missing security flags. This is critical for session security.`,
            evidence: `Secure: ${parsed.secure}, HttpOnly: ${parsed.httpOnly}, SameSite: ${parsed.sameSite || 'not set'}`,
            remediation: 'Configure Mendix runtime to set Secure, HttpOnly, and SameSite flags on session cookies.',
            reference: 'https://docs.mendix.com/refguide/custom-settings/'
          });
        }
      }
    }

  } catch (err) {
    findings.push({
      id: 'cookie-scan-error',
      title: 'Cookie Scan Error',
      category: 'Cookie Security',
      severity: 'info',
      description: `Could not complete cookie scan: ${err.message}`,
      evidence: err.code || err.message,
      remediation: 'Ensure the target URL is accessible.',
      reference: ''
    });
  }

  return findings;
}

function parseCookie(cookieStr) {
  const parts = cookieStr.split(';').map(p => p.trim());
  const [nameValue, ...attributes] = parts;
  const eqIndex = nameValue.indexOf('=');
  const name = eqIndex >= 0 ? nameValue.substring(0, eqIndex) : nameValue;
  const value = eqIndex >= 0 ? nameValue.substring(eqIndex + 1) : '';

  const cookie = {
    name: name.trim(),
    value: value.trim(),
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    expires: null,
    maxAge: null
  };

  for (const attr of attributes) {
    const lower = attr.toLowerCase();
    if (lower === 'secure') cookie.secure = true;
    else if (lower === 'httponly') cookie.httpOnly = true;
    else if (lower.startsWith('samesite=')) cookie.sameSite = attr.split('=')[1];
    else if (lower.startsWith('domain=')) cookie.domain = attr.split('=')[1];
    else if (lower.startsWith('path=')) cookie.path = attr.split('=')[1];
    else if (lower.startsWith('expires=')) cookie.expires = attr.split('=').slice(1).join('=');
    else if (lower.startsWith('max-age=')) cookie.maxAge = parseInt(attr.split('=')[1]);
  }

  return cookie;
}

function isSessionCookie(name) {
  const sessionNames = [
    'session', 'sessionid', 'sid', 'jsessionid', 'xassessionid',
    'phpsessid', 'asp.net_sessionid', 'connect.sid', 'sess'
  ];
  return sessionNames.some(sn => name.toLowerCase().includes(sn));
}

module.exports = { scan };
