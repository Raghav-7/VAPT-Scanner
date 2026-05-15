const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

// XSS test payloads — benign detection payloads (no actual exploitation)
const XSS_PAYLOADS = [
  { payload: '<script>alert("VAPTXSS1")</script>', name: 'Basic Script Tag', context: 'html' },
  { payload: '"><script>alert("VAPTXSS2")</script>', name: 'Attribute Breakout Script', context: 'attribute' },
  { payload: "'-alert('VAPTXSS3')-'", name: 'JS Context Injection', context: 'javascript' },
  { payload: '<img src=x onerror=alert("VAPTXSS4")>', name: 'IMG Event Handler', context: 'html' },
  { payload: '<svg onload=alert("VAPTXSS5")>', name: 'SVG Event Handler', context: 'html' },
  { payload: 'javascript:alert("VAPTXSS6")', name: 'JavaScript Protocol', context: 'href' },
  { payload: '"><img src=x onerror=alert(1)>', name: 'Attribute Breakout IMG', context: 'attribute' },
  { payload: "';alert('VAPTXSS8');//", name: 'JS String Escape', context: 'javascript' },
  { payload: '<details open ontoggle=alert(1)>', name: 'Details Toggle Handler', context: 'html' },
  { payload: '<body onload=alert(1)>', name: 'Body Onload Handler', context: 'html' },
  { payload: '{{constructor.constructor("alert(1)")()}}', name: 'Template Injection', context: 'template' },
  { payload: '${alert(1)}', name: 'Template Literal Injection', context: 'template' },
  { payload: '<iframe src="javascript:alert(1)">', name: 'IFrame JavaScript Src', context: 'html' },
  { payload: '<a href="javascript:alert(1)">click</a>', name: 'Anchor JavaScript Href', context: 'href' },
  { payload: '<div style="background:url(javascript:alert(1))">', name: 'CSS Expression', context: 'style' },
];

// Common parameter names to test
const COMMON_PARAMS = [
  'q', 'search', 'query', 'id', 'name', 'page', 'url', 'redirect',
  'return', 'next', 'callback', 'data', 'input', 'text', 'message',
  'content', 'title', 'value', 'param', 'action', 'file', 'path',
  'lang', 'type', 'category', 'ref', 'src', 'img', 'view'
];

async function scan(targetUrl, options = {}) {
  const findings = [];
  const url = new URL(targetUrl);

  // Phase 1: Analyze the page for potential XSS sinks
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
    });

    const html = response.data;
    if (typeof html === 'string') {
      const $ = cheerio.load(html);

      // Check for DOM XSS sinks in inline scripts
      const inlineScripts = [];
      $('script').each((_, el) => {
        const scriptContent = $(el).html();
        if (scriptContent) inlineScripts.push(scriptContent);
      });

      const domXssSinks = [
        { pattern: /document\.write\s*\(/g, name: 'document.write()' },
        { pattern: /\.innerHTML\s*=/g, name: 'innerHTML assignment' },
        { pattern: /\.outerHTML\s*=/g, name: 'outerHTML assignment' },
        { pattern: /eval\s*\(/g, name: 'eval()' },
        { pattern: /setTimeout\s*\(\s*['"]/g, name: 'setTimeout with string' },
        { pattern: /setInterval\s*\(\s*['"]/g, name: 'setInterval with string' },
        { pattern: /new\s+Function\s*\(/g, name: 'new Function()' },
        { pattern: /location\s*=|location\.href\s*=/g, name: 'Location assignment' },
        { pattern: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML()' },
        { pattern: /document\.domain\s*=/g, name: 'document.domain assignment' },
        { pattern: /window\.name/g, name: 'window.name usage' },
        { pattern: /location\.hash/g, name: 'location.hash usage' },
        { pattern: /location\.search/g, name: 'location.search usage' },
        { pattern: /document\.referrer/g, name: 'document.referrer usage' },
        { pattern: /document\.URL/g, name: 'document.URL usage' },
        { pattern: /postMessage/g, name: 'postMessage usage' },
      ];

      const allScript = inlineScripts.join('\n');
      for (const sink of domXssSinks) {
        const matches = allScript.match(sink.pattern);
        if (matches) {
          findings.push({
            id: `xss-dom-sink-${sink.name.replace(/[^a-z0-9]/gi, '')}`,
            title: `DOM XSS Sink Detected: ${sink.name}`,
            category: 'XSS',
            severity: 'medium',
            description: `Found ${matches.length} occurrence(s) of ${sink.name} in inline scripts. If user-controlled input reaches this sink, it could lead to DOM-based XSS.`,
            evidence: `Pattern: ${sink.name}, Occurrences: ${matches.length}`,
            remediation: `Avoid using ${sink.name} with untrusted data. Use safe alternatives like textContent or DOMPurify sanitization.`,
            reference: 'https://owasp.org/www-community/attacks/DOM_Based_XSS'
          });
        }
      }

      // Check for dangerous DOM sources
      const domSources = [
        { pattern: /document\.location/g, name: 'document.location' },
        { pattern: /window\.location/g, name: 'window.location' },
        { pattern: /document\.cookie/g, name: 'document.cookie' },
      ];

      for (const source of domSources) {
        const matches = allScript.match(source.pattern);
        if (matches) {
          // Check if any sink is also present
          const hasSink = domXssSinks.some(s => s.pattern.test(allScript));
          if (hasSink) {
            findings.push({
              id: `xss-dom-source-sink-${source.name.replace(/[^a-z0-9]/gi, '')}`,
              title: `DOM XSS Source-Sink Connection: ${source.name}`,
              category: 'XSS',
              severity: 'high',
              description: `Both DOM XSS sources (${source.name}) and sinks are present in inline scripts. This may indicate a DOM-based XSS vulnerability.`,
              evidence: `Source: ${source.name} (${matches.length} occurrences), Sinks detected in same script`,
              remediation: 'Review the data flow from source to sink. Sanitize all user-controlled input before passing to DOM manipulation functions.',
              reference: 'https://owasp.org/www-community/attacks/DOM_Based_XSS'
            });
          }
        }
      }

      // Check for forms without proper encoding
      $('form').each((idx, el) => {
        const method = ($(el).attr('method') || 'GET').toUpperCase();
        const action = $(el).attr('action') || '';
        const enctype = $(el).attr('enctype') || '';

        // Check for forms that might be vulnerable to reflected XSS
        if (method === 'GET') {
          findings.push({
            id: `xss-form-get-${idx}`,
            title: 'Form Using GET Method',
            category: 'XSS',
            severity: 'low',
            description: `A form uses GET method, which includes parameters in the URL. This increases the attack surface for reflected XSS.`,
            evidence: `Form action: ${action || 'self'}, Method: GET`,
            remediation: 'Use POST method for forms that process user input.',
            reference: 'https://owasp.org/www-community/attacks/xss/'
          });
        }
      });

      // Check for dangerous HTML attributes
      const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur', 'onsubmit', 'onchange'];
      for (const attr of dangerousAttrs) {
        const elements = $(`[${attr}]`);
        if (elements.length > 0) {
          findings.push({
            id: `xss-inline-handler-${attr}`,
            title: `Inline Event Handler: ${attr}`,
            category: 'XSS',
            severity: 'low',
            description: `Found ${elements.length} element(s) with inline ${attr} handlers. Inline event handlers can be an XSS vector.`,
            evidence: `Attribute: ${attr}, Count: ${elements.length}`,
            remediation: 'Use addEventListener() instead of inline event handlers. Implement CSP to block inline scripts.',
            reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
          });
        }
      }

      // Check for javascript: URLs
      $('a[href^="javascript:"], iframe[src^="javascript:"]').each((idx, el) => {
        findings.push({
          id: `xss-javascript-url-${idx}`,
          title: 'JavaScript URL Protocol',
          category: 'XSS',
          severity: 'medium',
          description: 'Found elements using javascript: protocol URLs, which can be exploited for XSS.',
          evidence: `Element: ${el.tagName}, href/src starts with javascript:`,
          remediation: 'Remove javascript: URLs. Use proper event handlers instead.',
          reference: 'https://owasp.org/www-community/attacks/xss/'
        });
      });
    }

  } catch (err) {
    findings.push({
      id: 'xss-page-analysis-error',
      title: 'XSS Page Analysis Error',
      category: 'XSS',
      severity: 'info',
      description: `Could not analyze page for XSS: ${err.message}`,
      evidence: err.code || err.message,
      remediation: 'Ensure the target is accessible.',
      reference: ''
    });
  }

  // Phase 2: Reflected XSS Testing
  // Test existing URL parameters
  const existingParams = url.searchParams;
  const paramsToTest = new Set();

  for (const [key] of existingParams) {
    paramsToTest.add(key);
  }

  // Also test common parameter names
  for (const p of COMMON_PARAMS) {
    paramsToTest.add(p);
  }

  // Test a subset of payloads for each parameter to avoid overwhelming the target
  const testPayloads = XSS_PAYLOADS.slice(0, 6); // Use top 6 payloads

  for (const param of paramsToTest) {
    for (const xss of testPayloads) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, xss.payload);

        const response = await axios.get(testUrl.toString(), {
          timeout: 10000,
          maxRedirects: 5,
          validateStatus: () => true,
          headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
        });

        if (typeof response.data === 'string') {
          // Check if payload is reflected without encoding
          if (response.data.includes(xss.payload)) {
            findings.push({
              id: `xss-reflected-${param}-${xss.name.replace(/\s+/g, '-')}`,
              title: `Reflected XSS: ${xss.name}`,
              category: 'XSS',
              severity: 'critical',
              description: `The payload "${xss.name}" is reflected unencoded in the response when injected via parameter "${param}". This indicates a reflected XSS vulnerability.`,
              evidence: `Parameter: ${param}, Payload: ${xss.payload}, Reflected in response body`,
              remediation: 'Encode all user input before reflecting in HTML output. Use context-appropriate output encoding (HTML entity encoding, JavaScript encoding, URL encoding).',
              reference: 'https://owasp.org/www-community/attacks/xss/'
            });
            break; // One finding per param is enough
          }

          // Check for partial reflection (might indicate encoding bypass opportunity)
          const strippedPayload = xss.payload.replace(/<[^>]*>/g, '').replace(/['"]/g, '');
          if (strippedPayload.length > 3 && response.data.includes(strippedPayload)) {
            // Check if the dangerous parts are stripped but content reflects
            if (!response.data.includes(xss.payload)) {
              findings.push({
                id: `xss-partial-reflection-${param}`,
                title: `Partial XSS Reflection Detected`,
                category: 'XSS',
                severity: 'medium',
                description: `Parameter "${param}" reflects user input with some sanitization but the sanitization may be bypassable.`,
                evidence: `Parameter: ${param}, Input partially reflected (tags stripped but content present)`,
                remediation: 'Use comprehensive output encoding rather than blacklist-based filtering. Implement CSP.',
                reference: 'https://owasp.org/www-community/attacks/xss/'
              });
              break;
            }
          }
        }
      } catch (err) {
        // Skip errors for individual tests
        continue;
      }
    }

    // Add a small delay between parameter tests to avoid rate limiting
    await sleep(100);
  }

  // Phase 3: Check CSP for XSS protection
  try {
    const response = await axios.get(targetUrl, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0', ...(options.headers || {}) }
    });

    const csp = response.headers['content-security-policy'];
    if (!csp) {
      findings.push({
        id: 'xss-no-csp',
        title: 'No Content Security Policy (XSS Protection)',
        category: 'XSS',
        severity: 'high',
        description: 'The application does not implement a Content Security Policy, which is a critical defense against XSS attacks.',
        evidence: 'Content-Security-Policy header not found',
        remediation: "Implement a strict CSP. Minimum: Content-Security-Policy: default-src 'self'; script-src 'self'",
        reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
      });
    }
  } catch (err) {
    // Skip
  }

  return findings;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { scan };
