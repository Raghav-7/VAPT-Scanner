const axios = require('axios');
const { URL } = require('url');

// SQL/OQL Injection payloads — benign detection payloads
const INJECTION_PAYLOADS = [
  // SQL Injection - Error Based
  { payload: "'", name: 'Single Quote', type: 'sql' },
  { payload: "' OR '1'='1", name: 'Boolean OR (Single Quote)', type: 'sql' },
  { payload: '" OR "1"="1', name: 'Boolean OR (Double Quote)', type: 'sql' },
  { payload: "' OR 1=1--", name: 'Boolean OR Comment', type: 'sql' },
  { payload: "' OR 1=1#", name: 'Boolean OR Hash Comment', type: 'sql' },
  { payload: "1' AND '1'='1", name: 'Boolean AND True', type: 'sql' },
  { payload: "1' AND '1'='2", name: 'Boolean AND False', type: 'sql' },
  { payload: "' UNION SELECT NULL--", name: 'UNION SELECT', type: 'sql' },
  { payload: "'; DROP TABLE test--", name: 'Statement Terminator', type: 'sql' },
  { payload: "1; WAITFOR DELAY '0:0:5'--", name: 'Time-based (MSSQL)', type: 'sql-time' },
  { payload: "1' AND SLEEP(5)--", name: 'Time-based (MySQL)', type: 'sql-time' },
  { payload: "1'; SELECT pg_sleep(5)--", name: 'Time-based (PostgreSQL)', type: 'sql-time' },

  // OQL Injection (Mendix-specific)
  { payload: "'] OR [1=1", name: 'OQL Boolean OR', type: 'oql' },
  { payload: "' OR ID > 0 OR '1'='1", name: 'OQL ID Enumeration', type: 'oql' },
  { payload: "[%'", name: 'OQL Wildcard Injection', type: 'oql' },

  // NoSQL Injection
  { payload: '{"$gt":""}', name: 'NoSQL GT Operator', type: 'nosql' },
  { payload: '{"$ne":""}', name: 'NoSQL NE Operator', type: 'nosql' },
  { payload: '{"$regex":".*"}', name: 'NoSQL Regex', type: 'nosql' },

  // LDAP Injection
  { payload: '*)(objectClass=*', name: 'LDAP Wildcard', type: 'ldap' },
  { payload: '*)(&', name: 'LDAP Filter Breakout', type: 'ldap' },

  // Command Injection
  { payload: '; ls -la', name: 'Unix Command Chain', type: 'command' },
  { payload: '| dir', name: 'Pipe Command (Windows)', type: 'command' },
  { payload: '`id`', name: 'Backtick Command', type: 'command' },
  { payload: '$(id)', name: 'Subshell Command', type: 'command' },

  // XPath Injection
  { payload: "' or '1'='1", name: 'XPath Boolean', type: 'xpath' },
  { payload: "1' or ''='", name: 'XPath String', type: 'xpath' },
];

// SQL error signatures
const SQL_ERROR_PATTERNS = [
  { pattern: /SQL syntax.*MySQL/i, db: 'MySQL' },
  { pattern: /Warning.*mysql_/i, db: 'MySQL' },
  { pattern: /MySqlException/i, db: 'MySQL' },
  { pattern: /valid MySQL result/i, db: 'MySQL' },
  { pattern: /PostgreSQL.*ERROR/i, db: 'PostgreSQL' },
  { pattern: /pg_query/i, db: 'PostgreSQL' },
  { pattern: /pg_exec/i, db: 'PostgreSQL' },
  { pattern: /PSQLException/i, db: 'PostgreSQL' },
  { pattern: /ORA-\d{5}/i, db: 'Oracle' },
  { pattern: /Oracle.*Driver/i, db: 'Oracle' },
  { pattern: /SQLServer.*Driver/i, db: 'MSSQL' },
  { pattern: /Microsoft.*ODBC/i, db: 'MSSQL' },
  { pattern: /mssql_query/i, db: 'MSSQL' },
  { pattern: /Unclosed quotation mark/i, db: 'MSSQL' },
  { pattern: /SqlException/i, db: 'MSSQL' },
  { pattern: /SQLite.*error/i, db: 'SQLite' },
  { pattern: /SQLITE_ERROR/i, db: 'SQLite' },
  { pattern: /sqlite3\.OperationalError/i, db: 'SQLite' },
  { pattern: /JDBC.*Exception/i, db: 'Java/JDBC' },
  { pattern: /java\.sql\.SQLException/i, db: 'Java/JDBC' },
  { pattern: /hibernate/i, db: 'Hibernate' },
  { pattern: /javax\.persistence/i, db: 'JPA' },
  { pattern: /com\.mendix/i, db: 'Mendix Runtime' },
  { pattern: /OQL.*error/i, db: 'Mendix OQL' },
  { pattern: /runtime\s+error/i, db: 'Generic' },
  { pattern: /syntax error/i, db: 'Generic' },
  { pattern: /unterminated string/i, db: 'Generic' },
  { pattern: /unexpected end of/i, db: 'Generic' },
];

const COMMON_PARAMS = [
  'id', 'user', 'name', 'query', 'search', 'q', 'page', 'sort',
  'order', 'filter', 'category', 'type', 'status', 'action', 'cmd',
  'file', 'dir', 'path', 'data', 'input', 'value', 'key', 'token'
];

async function scan(targetUrl, options = {}) {
  const findings = [];
  const url = new URL(targetUrl);

  // Collect parameters to test
  const paramsToTest = new Set();
  for (const [key] of url.searchParams) {
    paramsToTest.add(key);
  }
  for (const p of COMMON_PARAMS) {
    paramsToTest.add(p);
  }

  // Phase 1: Error-based injection testing
  for (const param of paramsToTest) {
    let vulnerablePayloads = [];

    for (const inj of INJECTION_PAYLOADS) {
      // Skip time-based payloads in normal mode (they take too long)
      if (inj.type === 'sql-time') continue;

      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, inj.payload);

        const startTime = Date.now();
        const response = await axios.get(testUrl.toString(), {
          timeout: 10000,
          maxRedirects: 5,
          validateStatus: () => true,
          headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
        });
        const responseTime = Date.now() - startTime;

        if (typeof response.data === 'string') {
          // Check for SQL error messages in response
          for (const errPattern of SQL_ERROR_PATTERNS) {
            if (errPattern.pattern.test(response.data)) {
              vulnerablePayloads.push({
                payload: inj.payload,
                name: inj.name,
                type: inj.type,
                db: errPattern.db,
                statusCode: response.status
              });
              break; // One pattern match per payload is enough
            }
          }

          // Check for stack traces or detailed error info
          if (/stack\s*trace/i.test(response.data) || /exception/i.test(response.data)) {
            if (!vulnerablePayloads.some(v => v.payload === inj.payload)) {
              findings.push({
                id: `injection-error-disclosure-${param}-${inj.name.replace(/\s+/g, '-')}`,
                title: `Error/Stack Trace Disclosure via ${param}`,
                category: 'Injection',
                severity: 'medium',
                description: `Injecting "${inj.name}" via parameter "${param}" caused the server to return error details or stack traces.`,
                evidence: `Parameter: ${param}, Payload: ${inj.payload}, Response Status: ${response.status}`,
                remediation: 'Implement custom error pages that do not reveal technical details. Log errors server-side only.',
                reference: 'https://owasp.org/www-community/Improper_Error_Handling'
              });
            }
          }
        }
      } catch (err) {
        continue;
      }
    }

    // Report injection findings for this parameter
    if (vulnerablePayloads.length > 0) {
      const bestMatch = vulnerablePayloads[0]; // Most relevant finding
      findings.push({
        id: `injection-${bestMatch.type}-${param}`,
        title: `${bestMatch.type.toUpperCase()} Injection: ${param}`,
        category: 'Injection',
        severity: 'critical',
        description: `The parameter "${param}" appears vulnerable to ${bestMatch.type.toUpperCase()} injection. Database error messages from ${bestMatch.db} were detected in the response when injecting "${bestMatch.name}" payload.`,
        evidence: `Parameter: ${param}, Payload: ${bestMatch.payload}, DB: ${bestMatch.db}, Vulnerable payloads: ${vulnerablePayloads.length}`,
        remediation: `Use parameterized queries/prepared statements. Never concatenate user input into queries. For Mendix: use proper XPath/OQL parameter binding.`,
        reference: 'https://owasp.org/www-community/attacks/SQL_Injection'
      });
    }

    await sleep(100);
  }

  // Phase 2: Boolean-based detection (comparing responses)
  for (const param of paramsToTest) {
    try {
      const trueUrl = new URL(targetUrl);
      trueUrl.searchParams.set(param, "1' OR '1'='1");
      const falseUrl = new URL(targetUrl);
      falseUrl.searchParams.set(param, "1' AND '1'='2");
      const normalUrl = new URL(targetUrl);
      normalUrl.searchParams.set(param, "1");

      const [trueResp, falseResp, normalResp] = await Promise.all([
        axios.get(trueUrl.toString(), { timeout: 8000, validateStatus: () => true, headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' } }),
        axios.get(falseUrl.toString(), { timeout: 8000, validateStatus: () => true, headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' } }),
        axios.get(normalUrl.toString(), { timeout: 8000, validateStatus: () => true, headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' } }),
      ]);

      const trueLen = (typeof trueResp.data === 'string') ? trueResp.data.length : 0;
      const falseLen = (typeof falseResp.data === 'string') ? falseResp.data.length : 0;
      const normalLen = (typeof normalResp.data === 'string') ? normalResp.data.length : 0;

      // If true-condition response is similar to normal but different from false-condition
      if (trueLen > 0 && falseLen > 0 && normalLen > 0) {
        const trueDiff = Math.abs(trueLen - normalLen) / normalLen;
        const falseDiff = Math.abs(falseLen - normalLen) / normalLen;

        if (trueDiff < 0.1 && falseDiff > 0.3) {
          // Check if not already reported as error-based
          if (!findings.some(f => f.id.includes(`injection-`) && f.id.includes(param))) {
            findings.push({
              id: `injection-boolean-${param}`,
              title: `Possible Boolean-Based SQL Injection: ${param}`,
              category: 'Injection',
              severity: 'high',
              description: `Parameter "${param}" shows different response lengths for true/false SQL conditions, suggesting boolean-based SQL injection.`,
              evidence: `Parameter: ${param}, Normal length: ${normalLen}, True condition length: ${trueLen}, False condition length: ${falseLen}`,
              remediation: 'Use parameterized queries. Review all database queries involving this parameter.',
              reference: 'https://owasp.org/www-community/attacks/SQL_Injection'
            });
          }
        }
      }
    } catch (err) {
      continue;
    }

    await sleep(100);
  }

  // Phase 3: Test POST endpoints for injection
  try {
    const response = await axios.get(targetUrl, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
    });

    // Find login/search forms to test
    if (typeof response.data === 'string') {
      const cheerio = require('cheerio');
      const $ = cheerio.load(response.data);

      $('form[method="post"], form[method="POST"]').each((idx, form) => {
        const action = $(form).attr('action') || '';
        const inputs = [];
        $(form).find('input[name]').each((_, inp) => {
          inputs.push($(inp).attr('name'));
        });

        if (inputs.length > 0) {
          findings.push({
            id: `injection-post-form-${idx}`,
            title: 'POST Form Detected (Manual Injection Testing Recommended)',
            category: 'Injection',
            severity: 'info',
            description: `A POST form was found with ${inputs.length} input(s). Manual testing for injection is recommended.`,
            evidence: `Action: ${action || 'self'}, Inputs: ${inputs.join(', ')}`,
            remediation: 'Ensure all form inputs are properly validated and parameterized on the server side.',
            reference: 'https://owasp.org/www-community/attacks/SQL_Injection'
          });
        }
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
