// Mendix VAPT Scanner — Remediation Guide
// Provides detailed, Mendix-specific fix instructions for each vulnerability category

const REMEDIATION_GUIDES = {
  'Security Headers': {
    overview: 'Security headers instruct browsers how to handle your app content. Missing headers leave the app vulnerable to XSS, clickjacking, and data theft.',
    steps: [
      {
        title: 'Add headers via Mendix Cloud Portal',
        description: 'Go to Mendix Portal → Environments → Your Environment → Network → HTTP Headers. Add each missing header.',
      },
      {
        title: 'Or configure via Nginx reverse proxy',
        code: `# Add to your Nginx server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# Hide technology disclosure
proxy_hide_header X-Powered-By;
proxy_hide_header Server;`,
      },
      {
        title: 'Fix CORS issues',
        description: 'Never use Access-Control-Allow-Origin: *. Instead, validate the Origin header against an allowlist of trusted domains in your Mendix REST service microflow.',
      }
    ]
  },

  'SSL/TLS': {
    overview: 'TLS encrypts all data between the browser and server. Weak or missing encryption exposes passwords, session tokens, and sensitive data.',
    steps: [
      {
        title: 'Enable HTTPS on Mendix Cloud',
        description: 'Mendix Cloud auto-provisions Let\'s Encrypt certificates. Go to Portal → Environments → Custom Domains to configure HTTPS for your domain.',
      },
      {
        title: 'For on-premises: Configure strong TLS',
        code: `# Nginx SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;

# Force HTTP → HTTPS redirect
server {
    listen 80;
    return 301 https://$host$request_uri;
}`,
      },
      {
        title: 'Renew certificates before expiry',
        description: 'Use certbot with auto-renewal for Let\'s Encrypt. Set monitoring alerts for certificate expiry (30 days before).',
      }
    ]
  },

  'Cookie Security': {
    overview: 'Cookies store session tokens. Without proper security flags, attackers can steal sessions via XSS or CSRF attacks.',
    steps: [
      {
        title: 'Configure Mendix session cookie security',
        code: `# Add to Mendix Runtime Settings:
com.mendix.core.SameSiteCookies=Strict
com.mendix.core.SessionTimeout=600`,
        description: 'In Studio Pro → App → Settings → Runtime → Add these custom settings.',
      },
      {
        title: 'For custom cookies in Java actions',
        code: `Cookie cookie = new Cookie("name", "value");
cookie.setSecure(true);      // Only HTTPS
cookie.setHttpOnly(true);    // Block JavaScript
cookie.setPath("/");
response.addCookie(cookie);`,
      },
      {
        title: 'Verify Mendix version',
        description: 'Mendix 9.12+ automatically sets Secure and HttpOnly flags on session cookies when HTTPS is enabled. Upgrade if you\'re on an older version.',
      }
    ]
  },

  'XSS': {
    overview: 'Cross-Site Scripting allows attackers to execute malicious JavaScript in users\' browsers, stealing sessions, credentials, and data.',
    steps: [
      {
        title: 'Enable Content Security Policy (primary defense)',
        code: `# Mendix Runtime Setting:
com.mendix.core.ContentSecurityPolicy=default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;`,
        description: 'CSP tells browsers which scripts are allowed to run, blocking injected malicious scripts.',
      },
      {
        title: 'Fix custom widgets (most common XSS source)',
        code: `// ❌ VULNERABLE — never do this:
element.innerHTML = userInput;
document.write(userInput);
eval(userInput);

// ✅ SAFE — use textContent:
element.textContent = userInput;

// ✅ If HTML needed, sanitize with DOMPurify:
element.innerHTML = DOMPurify.sanitize(userInput);`,
      },
      {
        title: 'Mendix page best practices',
        description: 'Use Text widgets (auto-escape by default) instead of HTML snippets. Never bind user-controlled data directly into HTML snippets. In nanoflows building HTML, always escape special characters (<, >, &, ", \').',
      },
      {
        title: 'Remove dangerous DOM patterns',
        description: 'Replace document.write() with DOM manipulation. Replace innerHTML assignments with textContent. Replace eval() with JSON.parse() for data. Use addEventListener() instead of inline onclick handlers.',
      }
    ]
  },

  'Injection': {
    overview: 'Injection attacks insert malicious queries into your application, potentially compromising the entire database, server, or authentication system.',
    steps: [
      {
        title: 'Use parameterized XPath in Mendix (most important)',
        code: `// ❌ VULNERABLE — string concatenation:
[Name = '" + $UserInput + "']

// ✅ SAFE — parameterized XPath:
[Name = $VariableName]`,
        description: 'In Studio Pro, ALWAYS use parameterized XPath constraints in Retrieve activities. Never build XPath/OQL by concatenating user input.',
      },
      {
        title: 'Fix Java action SQL queries',
        code: `// ❌ VULNERABLE:
String q = "SELECT * FROM users WHERE name = '" + input + "'";
stmt.executeQuery(q);

// ✅ SAFE — PreparedStatement:
String q = "SELECT * FROM users WHERE name = ?";
PreparedStatement ps = conn.prepareStatement(q);
ps.setString(1, input);
ps.executeQuery();`,
      },
      {
        title: 'Add input validation',
        description: 'Set Validation Rules on entities in Studio Pro. Use Regular Expression validation for format enforcement. Limit string lengths. Reject unexpected special characters in microflow logic.',
      },
      {
        title: 'Hide error details',
        code: `# Mendix Runtime Setting:
com.mendix.core.ShowDetailedErrors=false`,
        description: 'Configure custom error pages in App → Settings → Runtime to prevent database error messages from reaching users.',
      }
    ]
  },

  'SSRF': {
    overview: 'SSRF tricks your server into making requests to internal systems, potentially accessing cloud credentials, databases, or internal services.',
    steps: [
      {
        title: 'Validate URLs in microflows',
        description: 'Before any "Call REST" or "Call Web Service" activity, add a Decision to validate the URL: must start with https://, must NOT contain internal IPs (127.0.0.1, 10.*, 172.16.*, 192.168.*, 169.254.*).',
      },
      {
        title: 'Create a URL validation Java action',
        code: `public static boolean isUrlSafe(String url) {
    try {
        java.net.URL parsed = new java.net.URL(url);
        InetAddress addr = InetAddress.getByName(parsed.getHost());

        // Block internal IPs
        if (addr.isLoopbackAddress() ||
            addr.isLinkLocalAddress() ||
            addr.isSiteLocalAddress()) {
            return false;
        }
        // Block cloud metadata
        if (parsed.getHost().equals("169.254.169.254")) {
            return false;
        }
        return true;
    } catch (Exception e) { return false; }
}`,
      },
      {
        title: 'Use domain allowlists',
        description: 'Maintain a list of approved external domains. Only allow Call REST/Web Service to those domains. Block all other outbound requests.',
      },
      {
        title: 'Network-level protection',
        description: 'On AWS: Enable IMDSv2 (requires token for metadata). Configure firewall rules to block outbound connections to private IP ranges from the Mendix runtime.',
      }
    ]
  },

  'CSRF': {
    overview: 'CSRF tricks authenticated users into performing actions they didn\'t intend, like changing passwords or transferring data, by exploiting their active session.',
    steps: [
      {
        title: 'Enable Mendix built-in CSRF protection',
        code: `# Mendix Runtime Setting (should be ON by default):
com.mendix.core.CsrfProtection=true`,
      },
      {
        title: 'Set SameSite cookies',
        code: `# Mendix Runtime Setting:
com.mendix.core.SameSiteCookies=Strict`,
        description: 'SameSite=Strict prevents browsers from sending cookies with cross-origin requests.',
      },
      {
        title: 'Protect Published REST Services',
        description: 'Mendix REST services do NOT have automatic CSRF protection. In your service microflow: extract the Origin header, validate it against your allowed domains, return 403 if invalid. Or require a custom header like X-Requested-With.',
      },
      {
        title: 'Use POST for state changes',
        description: 'Never use GET requests for operations that modify data (delete, update, create). GET requests can be triggered by img tags and links without user consent.',
      }
    ]
  },

  'Broken Access Control': {
    overview: 'Access control failures let unauthorized users view restricted data, access admin panels, or modify other users\' information.',
    steps: [
      {
        title: 'Set Security to Production level',
        description: 'In Studio Pro → App → Security → set to Production. This enforces all access rules.',
      },
      {
        title: 'Configure entity access rules (critical)',
        code: `For EVERY entity in your domain model:
1. Open entity → Access Rules tab
2. Set permissions per user role
3. Add XPath constraint for row-level security:
   [System.owner = '[%CurrentUser%]']
4. Limit readable/writable attributes per role`,
      },
      {
        title: 'Set page and microflow access',
        description: 'For every Page: set Allowed Roles (only roles that should see it). For every Microflow: set Allowed Roles in properties. Never leave pages/microflows with "All" roles in production.',
      },
      {
        title: 'Block admin endpoints in production',
        code: `# Nginx — block Mendix admin
location /_mxadmin/ { deny all; return 404; }
location /debugger/  { deny all; return 404; }`,
        description: 'Or in Mendix Cloud Portal: Environments → Details → Restrict admin page access to specific IPs.',
      },
      {
        title: 'Prevent IDOR vulnerabilities',
        description: 'Never retrieve objects by ID alone. Always add an ownership or role check: Retrieve [ID = $RequestedID AND Owner = \'[%CurrentUser%]\'].',
      }
    ]
  },

  'Security Misconfiguration': {
    overview: 'Misconfigurations expose sensitive files, debug information, and server details that help attackers understand and exploit your application.',
    steps: [
      {
        title: 'Block sensitive files at web server level',
        code: `# Nginx — block sensitive files
location ~ /\\.(env|git|svn|htaccess) { deny all; return 404; }
location ~ \\.(sql|bak|backup|yml|yaml|log)$ { deny all; return 404; }
location /m2ee.yaml { deny all; return 404; }
location /model-metadata.json { deny all; return 404; }`,
      },
      {
        title: 'Configure custom error pages',
        code: `# Mendix Runtime Setting:
com.mendix.core.ShowDetailedErrors=false`,
        description: 'In Studio Pro → App → Settings → Runtime → set custom Error page and 404 page. Never show stack traces in production.',
      },
      {
        title: 'Remove debug artifacts before deployment',
        description: 'Remove console.log() from custom widgets. Disable source maps in production widget builds. Remove HTML comments with sensitive info. Set Mendix log level to Warning or Error.',
      },
      {
        title: 'Disable directory listing',
        code: `# Nginx
autoindex off;`,
      }
    ]
  },

  'Cryptographic Failures': {
    overview: 'Cryptographic failures expose sensitive data through weak encryption, hardcoded secrets, or transmitting data without protection.',
    steps: [
      {
        title: 'Never expose secrets in client-side code',
        code: `// ❌ NEVER — key in widget JavaScript:
const API_KEY = "sk-live-abc123";

// ✅ SAFE — use Mendix Constants:
// 1. Create Constant in Studio Pro
// 2. Set value in Cloud Portal per environment
// 3. Reference in microflows: @Module.APIKey`,
      },
      {
        title: 'Use Mendix Constants for all secrets',
        description: 'In Studio Pro → App → Constants. Create constants for API keys, passwords, tokens. Set actual values per environment in Mendix Cloud Portal → Environment → Constants.',
      },
      {
        title: 'Never put sensitive data in URLs',
        description: 'Use POST request body instead of URL parameters for passwords, tokens, and PII. URLs are logged in browser history, server logs, and proxy logs.',
      },
      {
        title: 'Enforce HTTPS everywhere',
        description: 'Enable HTTPS in Mendix Cloud Portal. Configure HTTP→HTTPS redirect. Add HSTS header to prevent downgrade attacks.',
      }
    ]
  },

  'Mendix-Specific': {
    overview: 'Mendix platform has unique attack surfaces including the XAS runtime API, OData services, admin console, and anonymous user capabilities.',
    steps: [
      {
        title: 'Restrict Mendix Admin Console',
        description: 'In Mendix Cloud Portal → Environments → Details → Restrict Admin Page Access. Set to specific office IP addresses only. For on-premises: block /_mxadmin/ and /debugger/ at the proxy.',
      },
      {
        title: 'Fix user enumeration via XAS',
        code: `In Studio Pro → Security → User Roles:
1. Anonymous role: NO access to System.User
2. Domain Model → System.User → Access Rules
3. Remove read permissions for non-admin roles
4. Apply XPath: [id = '[%CurrentUser%]']`,
      },
      {
        title: 'Secure OData and REST services',
        description: 'For each Published Service: set Authentication to required (not anonymous). Set Allowed Roles to specific user roles. Limit exposed attributes — never expose IDs, passwords, or internal fields.',
      },
      {
        title: 'Configure anonymous access properly',
        code: `In Studio Pro → Security → Anonymous Users:
- If not needed: DISABLE entirely
- If needed: Create minimal "Anonymous" role
  → Minimal page access
  → Read-only entity access
  → XPath constraints on every entity`,
      },
      {
        title: 'Keep Mendix updated',
        description: 'Always run the latest patch of your Mendix version. Check docs.mendix.com/releasenotes for security fixes. Plan major upgrades every 12-18 months.',
      },
      {
        title: 'Hide version information',
        code: `# Nginx — remove Mendix headers
proxy_hide_header X-Mx-Trace-Id;
proxy_hide_header Mendix-Version;
proxy_hide_header X-Mendix-Cloud;`,
      }
    ]
  }
};

// Get remediation guide for a finding
function getRemediationGuide(finding) {
  const guide = REMEDIATION_GUIDES[finding.category];
  if (!guide) return null;
  return guide;
}

// Render remediation HTML for a finding
function renderRemediationHTML(finding) {
  const guide = getRemediationGuide(finding);
  if (!guide) {
    return `<div class="fix-section"><div class="fix-text">${escapeHtml(finding.remediation)}</div></div>`;
  }

  let html = `<div class="fix-guide">`;
  html += `<div class="fix-overview">${escapeHtml(guide.overview)}</div>`;
  html += `<div class="fix-steps">`;

  guide.steps.forEach((step, i) => {
    html += `<div class="fix-step">`;
    html += `<div class="fix-step-header"><span class="fix-step-num">${i + 1}</span><span class="fix-step-title">${escapeHtml(step.title)}</span></div>`;
    if (step.description) {
      html += `<div class="fix-step-desc">${escapeHtml(step.description)}</div>`;
    }
    if (step.code) {
      html += `<pre class="fix-code"><code>${escapeHtml(step.code)}</code></pre>`;
    }
    html += `</div>`;
  });

  html += `</div></div>`;
  return html;
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
