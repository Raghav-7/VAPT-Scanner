const tls = require('tls');
const https = require('https');
const { URL } = require('url');

async function scan(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);

  // Check if HTTPS is used
  if (url.protocol !== 'https:') {
    findings.push({
      id: 'ssl-no-https',
      title: 'No HTTPS Encryption',
      category: 'SSL/TLS',
      severity: 'critical',
      description: 'The application is served over HTTP without encryption. All data transmitted between the client and server can be intercepted.',
      evidence: `Protocol: ${url.protocol}`,
      remediation: 'Enable HTTPS with a valid TLS certificate. Use HSTS to enforce HTTPS.',
      reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
    });
    return findings; // Cannot check TLS on HTTP
  }

  // Check TLS certificate and configuration
  try {
    const certInfo = await getCertificateInfo(url.hostname, url.port || 443);

    // Check certificate expiry
    const expiryDate = new Date(certInfo.valid_to);
    const now = new Date();
    const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));

    if (daysUntilExpiry < 0) {
      findings.push({
        id: 'ssl-cert-expired',
        title: 'SSL Certificate Expired',
        category: 'SSL/TLS',
        severity: 'critical',
        description: `The SSL certificate expired on ${certInfo.valid_to}.`,
        evidence: `Certificate valid until: ${certInfo.valid_to}`,
        remediation: 'Renew the SSL certificate immediately.',
        reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
      });
    } else if (daysUntilExpiry < 30) {
      findings.push({
        id: 'ssl-cert-expiring-soon',
        title: 'SSL Certificate Expiring Soon',
        category: 'SSL/TLS',
        severity: 'medium',
        description: `The SSL certificate expires in ${daysUntilExpiry} days (${certInfo.valid_to}).`,
        evidence: `Certificate valid until: ${certInfo.valid_to}, Days remaining: ${daysUntilExpiry}`,
        remediation: 'Renew the SSL certificate before expiration.',
        reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
      });
    }

    // Check certificate issuer (self-signed)
    if (certInfo.issuer && certInfo.subject &&
        JSON.stringify(certInfo.issuer) === JSON.stringify(certInfo.subject)) {
      findings.push({
        id: 'ssl-self-signed',
        title: 'Self-Signed SSL Certificate',
        category: 'SSL/TLS',
        severity: 'high',
        description: 'The SSL certificate is self-signed, which means it cannot be verified by a trusted Certificate Authority.',
        evidence: `Issuer: ${JSON.stringify(certInfo.issuer)}, Subject: ${JSON.stringify(certInfo.subject)}`,
        remediation: 'Use a certificate signed by a trusted Certificate Authority (e.g., Let\'s Encrypt).',
        reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
      });
    }

    // Check TLS version
    if (certInfo.protocol) {
      const protocol = certInfo.protocol;
      if (protocol === 'TLSv1' || protocol === 'TLSv1.1' || protocol === 'SSLv3') {
        findings.push({
          id: 'ssl-weak-protocol',
          title: 'Weak TLS Protocol Version',
          category: 'SSL/TLS',
          severity: 'high',
          description: `The server supports ${protocol}, which has known vulnerabilities.`,
          evidence: `Protocol: ${protocol}`,
          remediation: 'Disable TLS 1.0 and 1.1. Use TLS 1.2 or 1.3 only.',
          reference: 'https://www.rfc-editor.org/rfc/rfc8996'
        });
      } else {
        findings.push({
          id: 'ssl-protocol-info',
          title: 'TLS Protocol Version',
          category: 'SSL/TLS',
          severity: 'info',
          description: `The server uses ${protocol}.`,
          evidence: `Protocol: ${protocol}`,
          remediation: 'No action required.',
          reference: ''
        });
      }
    }

    // Check cipher strength
    if (certInfo.cipher) {
      const weakCiphers = ['RC4', 'DES', '3DES', 'RC2', 'IDEA', 'SEED', 'NULL', 'EXPORT', 'anon'];
      const cipherName = certInfo.cipher.name || '';
      const isWeak = weakCiphers.some(wc => cipherName.toUpperCase().includes(wc));

      if (isWeak) {
        findings.push({
          id: 'ssl-weak-cipher',
          title: 'Weak Cipher Suite',
          category: 'SSL/TLS',
          severity: 'high',
          description: `The server uses a weak cipher suite: ${cipherName}`,
          evidence: `Cipher: ${cipherName}, Bits: ${certInfo.cipher.bits || 'unknown'}`,
          remediation: 'Configure the server to use strong cipher suites only (AES-256-GCM, CHACHA20-POLY1305).',
          reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
        });
      }

      if (certInfo.cipher.bits && certInfo.cipher.bits < 128) {
        findings.push({
          id: 'ssl-weak-key-length',
          title: 'Weak Cipher Key Length',
          category: 'SSL/TLS',
          severity: 'high',
          description: `The cipher key length is only ${certInfo.cipher.bits} bits, which is considered weak.`,
          evidence: `Cipher: ${cipherName}, Key Length: ${certInfo.cipher.bits} bits`,
          remediation: 'Use cipher suites with at least 128-bit key length (256-bit recommended).',
          reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'
        });
      }
    }

  } catch (err) {
    if (err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'CERT_HAS_EXPIRED' || 
        err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err.code === 'SELF_SIGNED_CERT_IN_CHAIN') {
      findings.push({
        id: 'ssl-cert-issue',
        title: 'SSL Certificate Validation Failed',
        category: 'SSL/TLS',
        severity: 'high',
        description: `SSL certificate validation failed: ${err.code}`,
        evidence: `Error: ${err.message}`,
        remediation: 'Fix the SSL certificate chain. Ensure all intermediate certificates are properly configured.',
        reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
      });
    } else {
      findings.push({
        id: 'ssl-scan-error',
        title: 'SSL/TLS Scan Error',
        category: 'SSL/TLS',
        severity: 'info',
        description: `Could not complete SSL/TLS analysis: ${err.message}`,
        evidence: err.code || err.message,
        remediation: 'Ensure the target supports HTTPS.',
        reference: ''
      });
    }
  }

  // Test for HTTP to HTTPS redirect
  if (url.protocol === 'https:') {
    try {
      const httpUrl = targetUrl.replace('https://', 'http://');
      const http = require('http');
      const redirectCheck = await new Promise((resolve, reject) => {
        const req = http.get(httpUrl, { timeout: 10000 }, (res) => {
          resolve({
            statusCode: res.statusCode,
            location: res.headers.location
          });
          res.resume();
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      });

      if (redirectCheck.statusCode >= 300 && redirectCheck.statusCode < 400) {
        if (redirectCheck.location && redirectCheck.location.startsWith('https://')) {
          findings.push({
            id: 'ssl-http-redirect',
            title: 'HTTP to HTTPS Redirect Present',
            category: 'SSL/TLS',
            severity: 'info',
            description: 'The server properly redirects HTTP requests to HTTPS.',
            evidence: `HTTP ${redirectCheck.statusCode} -> ${redirectCheck.location}`,
            remediation: 'No action required. This is a good security practice.',
            reference: ''
          });
        }
      } else if (redirectCheck.statusCode === 200) {
        findings.push({
          id: 'ssl-no-redirect',
          title: 'No HTTP to HTTPS Redirect',
          category: 'SSL/TLS',
          severity: 'medium',
          description: 'The server serves content over HTTP without redirecting to HTTPS.',
          evidence: `HTTP request returned status ${redirectCheck.statusCode} instead of redirect`,
          remediation: 'Configure the server to redirect all HTTP requests to HTTPS.',
          reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'
        });
      }
    } catch (err) {
      // HTTP port might not be open, which is actually fine
    }
  }

  return findings;
}

function getCertificateInfo(hostname, port) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false, // We want to inspect even invalid certs
      timeout: 10000
    };

    const socket = tls.connect(options, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();

        socket.end();
        resolve({
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          issuer: cert.issuer,
          subject: cert.subject,
          fingerprint: cert.fingerprint,
          serialNumber: cert.serialNumber,
          protocol,
          cipher,
          authorized: socket.authorized
        });
      } catch (err) {
        socket.end();
        reject(err);
      }
    });

    socket.on('error', reject);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('TLS connection timeout'));
    });
  });
}

module.exports = { scan };
