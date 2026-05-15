const axios = require('axios');
const tls = require('tls');
const { URL } = require('url');

async function scan(targetUrl, options = {}) {
  const findings = [];
  const url = new URL(targetUrl);

  // Phase 1: Check for HTTPS usage
  if (url.protocol !== 'https:') {
    findings.push({
      id: 'crypto-no-encryption',
      title: 'No Transport Encryption (HTTP)',
      category: 'Cryptographic Failures',
      severity: 'critical',
      description: 'The application uses HTTP without encryption. All data including credentials, session tokens, and sensitive information is transmitted in plaintext.',
      evidence: `Protocol: ${url.protocol}`,
      remediation: 'Enable HTTPS with a valid TLS 1.2+ certificate. Redirect all HTTP traffic to HTTPS.',
      reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    });
  }

  // Phase 2: Check for sensitive data in URLs
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
    });

    // Check URL parameters for sensitive data
    const sensitiveParamPatterns = [
      { pattern: /password/i, name: 'password' },
      { pattern: /passwd/i, name: 'password' },
      { pattern: /secret/i, name: 'secret' },
      { pattern: /token/i, name: 'token' },
      { pattern: /api.?key/i, name: 'API key' },
      { pattern: /auth/i, name: 'auth data' },
      { pattern: /credit.?card/i, name: 'credit card' },
      { pattern: /ssn/i, name: 'SSN' },
      { pattern: /session/i, name: 'session' },
    ];

    for (const [key, value] of url.searchParams) {
      for (const sp of sensitiveParamPatterns) {
        if (sp.pattern.test(key)) {
          findings.push({
            id: `crypto-sensitive-url-${key}`,
            title: `Sensitive Data in URL: ${sp.name}`,
            category: 'Cryptographic Failures',
            severity: 'high',
            description: `URL parameter "${key}" appears to contain ${sp.name} data. URLs are logged in browser history, server logs, and proxy logs.`,
            evidence: `Parameter: ${key}=${value.substring(0, 5)}...`,
            remediation: 'Never transmit sensitive data in URL parameters. Use POST request body or HTTP headers.',
            reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
          });
        }
      }
    }

    // Check for sensitive data in HTML (forms with autocomplete)
    if (typeof response.data === 'string') {
      const cheerio = require('cheerio');
      const $ = cheerio.load(response.data);

      // Check password fields
      $('input[type="password"]').each((idx, el) => {
        const autocomplete = $(el).attr('autocomplete');
        if (!autocomplete || autocomplete !== 'off') {
          findings.push({
            id: `crypto-password-autocomplete-${idx}`,
            title: 'Password Field Allows Autocomplete',
            category: 'Cryptographic Failures',
            severity: 'low',
            description: 'Password input fields do not disable autocomplete. Browsers may cache sensitive credentials.',
            evidence: `Input: ${$(el).attr('name') || $(el).attr('id') || 'unnamed'}, autocomplete: ${autocomplete || 'default (on)'}`,
            remediation: 'Add autocomplete="off" or autocomplete="new-password" to password fields.',
            reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
          });
        }
      });

      // Check for sensitive data in HTML comments
      const htmlComments = response.data.match(/<!--[\s\S]*?-->/g) || [];
      for (const comment of htmlComments) {
        const sensitiveInComment = /password|secret|key|token|credential|api_key|private/i.test(comment);
        if (sensitiveInComment) {
          findings.push({
            id: 'crypto-sensitive-html-comment',
            title: 'Sensitive Data in HTML Comments',
            category: 'Cryptographic Failures',
            severity: 'medium',
            description: 'HTML comments contain references to sensitive data (passwords, keys, tokens). This information is visible to anyone viewing the page source.',
            evidence: `Comment snippet: ${comment.substring(0, 100)}...`,
            remediation: 'Remove all comments containing sensitive information from production HTML.',
            reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
          });
          break; // One finding is enough
        }
      }

      // Check for exposed API keys or tokens in JavaScript
      const scripts = [];
      $('script').each((_, el) => {
        const src = $(el).attr('src');
        const content = $(el).html();
        if (content) scripts.push(content);
      });

      const allScript = scripts.join('\n');
      const secretPatterns = [
        { pattern: /['"](?:sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{20,}['"]/g, name: 'Stripe API Key' },
        { pattern: /['"]AIza[a-zA-Z0-9-_]{35}['"]/g, name: 'Google API Key' },
        { pattern: /['"]AKIA[A-Z0-9]{16}['"]/g, name: 'AWS Access Key' },
        { pattern: /['"]ghp_[a-zA-Z0-9]{36}['"]/g, name: 'GitHub Token' },
        { pattern: /['"]xox[baprs]-[a-zA-Z0-9-]{10,}['"]/g, name: 'Slack Token' },
        { pattern: /['"][a-f0-9]{32}['"]/g, name: 'Potential API Key (32-char hex)' },
        { pattern: /password\s*[:=]\s*['"][^'"]+['"]/gi, name: 'Hardcoded Password' },
        { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi, name: 'Hardcoded API Key' },
        { pattern: /secret\s*[:=]\s*['"][^'"]+['"]/gi, name: 'Hardcoded Secret' },
      ];

      for (const sp of secretPatterns) {
        const matches = allScript.match(sp.pattern);
        if (matches) {
          findings.push({
            id: `crypto-exposed-secret-${sp.name.replace(/\s+/g, '-')}`,
            title: `Exposed Secret in JavaScript: ${sp.name}`,
            category: 'Cryptographic Failures',
            severity: sp.name.includes('Potential') ? 'medium' : 'critical',
            description: `Found ${matches.length} potential ${sp.name}(s) in inline JavaScript. API keys and secrets should never be exposed in client-side code.`,
            evidence: `Pattern: ${sp.name}, Matches: ${matches.length}, Sample: ${matches[0].substring(0, 30)}...`,
            remediation: 'Remove all secrets from client-side code. Use environment variables and server-side API calls.',
            reference: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
          });
        }
      }
    }

    // Phase 3: Check response headers for crypto issues
    const headers = response.headers;

    // Check for sensitive response headers
    if (headers['www-authenticate'] && headers['www-authenticate'].toLowerCase().includes('basic')) {
      findings.push({
        id: 'crypto-basic-auth',
        title: 'HTTP Basic Authentication Used',
        category: 'Cryptographic Failures',
        severity: url.protocol === 'https:' ? 'medium' : 'critical',
        description: `The server uses HTTP Basic Authentication, which transmits credentials in Base64 encoding (easily decodable).${url.protocol !== 'https:' ? ' Combined with lack of HTTPS, credentials are transmitted in plaintext.' : ''}`,
        evidence: `WWW-Authenticate: ${headers['www-authenticate']}`,
        remediation: 'Use token-based authentication (OAuth 2.0, JWT). If Basic Auth is required, ensure HTTPS is used.',
        reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
      });
    }

  } catch (err) {
    findings.push({
      id: 'crypto-scan-error',
      title: 'Cryptographic Scan Error',
      category: 'Cryptographic Failures',
      severity: 'info',
      description: `Could not complete cryptographic analysis: ${err.message}`,
      evidence: err.code || err.message,
      remediation: 'Ensure the target is accessible.',
      reference: ''
    });
  }

  // Phase 4: TLS cipher analysis (if HTTPS)
  if (url.protocol === 'https:') {
    try {
      const certInfo = await getTlsInfo(url.hostname, url.port || 443);

      // Check for weak key exchange
      if (certInfo.cipher && certInfo.cipher.name) {
        const cipher = certInfo.cipher.name;
        if (/DHE/.test(cipher) && !/ECDHE/.test(cipher)) {
          findings.push({
            id: 'crypto-weak-key-exchange',
            title: 'Weak Key Exchange (DHE without ECDHE)',
            category: 'Cryptographic Failures',
            severity: 'medium',
            description: `The cipher suite uses DHE key exchange instead of ECDHE, which may be vulnerable to Logjam attacks.`,
            evidence: `Cipher: ${cipher}`,
            remediation: 'Prefer ECDHE key exchange. Disable DHE ciphers.',
            reference: 'https://weakdh.org/'
          });
        }

        // Check for forward secrecy
        if (!/DHE|ECDHE/.test(cipher)) {
          findings.push({
            id: 'crypto-no-forward-secrecy',
            title: 'No Forward Secrecy',
            category: 'Cryptographic Failures',
            severity: 'medium',
            description: 'The cipher suite does not provide forward secrecy. If the server\'s private key is compromised, all past communications can be decrypted.',
            evidence: `Cipher: ${cipher}`,
            remediation: 'Use cipher suites with (EC)DHE key exchange for forward secrecy.',
            reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'
          });
        }

        // Check for AEAD
        if (!/GCM|CCM|POLY1305|CHACHA/i.test(cipher)) {
          findings.push({
            id: 'crypto-no-aead',
            title: 'Non-AEAD Cipher Suite',
            category: 'Cryptographic Failures',
            severity: 'low',
            description: 'The cipher suite does not use Authenticated Encryption with Associated Data (AEAD). AEAD ciphers provide better security guarantees.',
            evidence: `Cipher: ${cipher}`,
            remediation: 'Prefer AEAD cipher suites (AES-GCM, CHACHA20-POLY1305).',
            reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'
          });
        }
      }

    } catch (err) {
      // TLS info already covered by SSL scanner
    }
  }

  return findings;
}

function getTlsInfo(hostname, port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 10000
    }, () => {
      try {
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        socket.end();
        resolve({ cipher, protocol });
      } catch (err) {
        socket.end();
        reject(err);
      }
    });

    socket.on('error', reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('Timeout')); });
  });
}

module.exports = { scan };
