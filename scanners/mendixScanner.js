const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

// Mendix-specific endpoints and paths
const MENDIX_ENDPOINTS = [
  { path: '/xas/', name: 'XAS Runtime API', severity: 'medium', description: 'Mendix runtime API endpoint for client-server communication' },
  { path: '/odata/v1/', name: 'OData v1 Service', severity: 'medium', description: 'Mendix OData service for data integration' },
  { path: '/odata/', name: 'OData Services', severity: 'medium', description: 'Mendix OData base endpoint' },
  { path: '/rest/', name: 'REST Services', severity: 'medium', description: 'Mendix published REST services' },
  { path: '/ws/', name: 'Web Services (SOAP)', severity: 'medium', description: 'Mendix published SOAP web services' },
  { path: '/api/', name: 'API Endpoint', severity: 'medium', description: 'Mendix API endpoint' },
  { path: '/api-doc/', name: 'API Documentation', severity: 'medium', description: 'Mendix auto-generated API documentation' },
  { path: '/api-doc/catalog/', name: 'API Catalog', severity: 'medium', description: 'Mendix API catalog' },
  { path: '/_mxadmin/', name: 'Mendix Admin Console', severity: 'critical', description: 'Mendix administration console for managing the runtime' },
  { path: '/_mxadmin/runtime/', name: 'Runtime Admin', severity: 'critical', description: 'Runtime administration page' },
  { path: '/debugger/', name: 'Mendix Debugger', severity: 'critical', description: 'Mendix microflow debugger - should never be exposed in production' },
  { path: '/login.html', name: 'Default Login Page', severity: 'info', description: 'Standard Mendix login page' },
  { path: '/index.html', name: 'Main Application', severity: 'info', description: 'Mendix application entry point' },
  { path: '/mxclientsystem/', name: 'Client System Files', severity: 'low', description: 'Mendix client-side system files' },
  { path: '/widgets/', name: 'Widget Resources', severity: 'low', description: 'Mendix widget files directory' },
  { path: '/p/', name: 'Deep Link Pages', severity: 'info', description: 'Mendix deep-link enabled pages' },
  { path: '/link/', name: 'Link Resolver', severity: 'low', description: 'Mendix link resolver endpoint' },
  { path: '/file', name: 'File Handler', severity: 'medium', description: 'Mendix file download handler' },
];

// Mendix-specific headers
const MENDIX_HEADERS = [
  'x-mx-trace-id',
  'x-mx-request-id',
  'mendix-version',
  'x-mendix-cloud',
];

async function scan(targetUrl, options = {}) {
  const findings = [];
  const url = new URL(targetUrl);

  // Phase 1: Detect Mendix Application
  let isMendix = false;
  let mendixVersion = null;

  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
    });

    const html = typeof response.data === 'string' ? response.data : '';
    const headers = response.headers;

    // Check for Mendix indicators in HTML
    const mendixIndicators = [
      { pattern: /mxui/i, name: 'Mendix UI Framework (mxui)' },
      { pattern: /mendix/i, name: 'Mendix Reference' },
      { pattern: /mx\.data/i, name: 'Mendix Client API (mx.data)' },
      { pattern: /mx\.session/i, name: 'Mendix Session API (mx.session)' },
      { pattern: /mxclientsystem/i, name: 'Mendix Client System' },
      { pattern: /dojoConfig/i, name: 'Dojo Config (Mendix 7/8)' },
      { pattern: /com\.mendix/i, name: 'Mendix Package Reference' },
    ];

    for (const indicator of mendixIndicators) {
      if (indicator.pattern.test(html)) {
        isMendix = true;
        break;
      }
    }

    // Check Mendix headers
    for (const mh of MENDIX_HEADERS) {
      if (headers[mh]) {
        isMendix = true;
        if (mh === 'mendix-version') {
          mendixVersion = headers[mh];
        }

        findings.push({
          id: `mendix-header-disclosure-${mh}`,
          title: `Mendix Header Disclosure: ${mh}`,
          category: 'Mendix-Specific',
          severity: 'info',
          description: `The Mendix-specific header "${mh}" is present, confirming this is a Mendix application and revealing implementation details.`,
          evidence: `${mh}: ${headers[mh]}`,
          remediation: 'Consider removing or masking Mendix-specific headers in production to reduce information disclosure.',
          reference: 'https://docs.mendix.com/refguide/custom-settings/'
        });
      }
    }

    // Detect Mendix version from HTML
    if (!mendixVersion && html) {
      const versionMatches = html.match(/mendix[- ]?(\d+\.[\d.]+)/i) || 
                              html.match(/mxclientsystem\/(\d+\.[\d.]+)/i) ||
                              html.match(/client\/(\d+\.[\d.]+)/i);
      if (versionMatches) {
        mendixVersion = versionMatches[1];
      }
    }

    if (mendixVersion) {
      findings.push({
        id: 'mendix-version-disclosed',
        title: `Mendix Version Detected: ${mendixVersion}`,
        category: 'Mendix-Specific',
        severity: 'low',
        description: `Mendix runtime version ${mendixVersion} detected. Knowing the exact version helps attackers find known vulnerabilities.`,
        evidence: `Version: ${mendixVersion}`,
        remediation: 'Remove version information from responses. Keep Mendix runtime updated to the latest security patch.',
        reference: 'https://docs.mendix.com/releasenotes/'
      });

      // Check for known vulnerable versions
      const majorVersion = parseInt(mendixVersion.split('.')[0]);
      if (majorVersion < 8) {
        findings.push({
          id: 'mendix-outdated-major',
          title: `Outdated Mendix Version (Pre-8.x)`,
          category: 'Mendix-Specific',
          severity: 'high',
          description: `Mendix ${mendixVersion} is a significantly outdated version that may have unpatched security vulnerabilities.`,
          evidence: `Version: ${mendixVersion}`,
          remediation: 'Upgrade to Mendix 9.x or 10.x for the latest security patches and features.',
          reference: 'https://docs.mendix.com/releasenotes/'
        });
      }
    }

    if (isMendix) {
      findings.push({
        id: 'mendix-detected',
        title: 'Mendix Application Confirmed',
        category: 'Mendix-Specific',
        severity: 'info',
        description: 'This application is confirmed to be built with the Mendix platform.',
        evidence: 'Mendix indicators found in HTML/headers',
        remediation: 'This is informational. Ensure Mendix-specific security best practices are followed.',
        reference: 'https://docs.mendix.com/howto/security/'
      });
    }

  } catch (err) {
    findings.push({
      id: 'mendix-detection-error',
      title: 'Mendix Detection Error',
      category: 'Mendix-Specific',
      severity: 'info',
      description: `Could not perform Mendix detection: ${err.message}`,
      evidence: err.code || err.message,
      remediation: 'Ensure the target is accessible.',
      reference: ''
    });
  }

  // Phase 2: Check Mendix-specific endpoints
  for (const ep of MENDIX_ENDPOINTS) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.pathname = ep.path;

      const response = await axios.get(testUrl.toString(), {
        timeout: 8000,
        maxRedirects: 3,
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
      });

      if (response.status === 200 || response.status === 401) {
        const bodyLen = typeof response.data === 'string' ? response.data.length :
                        typeof response.data === 'object' ? JSON.stringify(response.data).length : 0;

        if (bodyLen > 50 || response.status === 401) {
          const isRestricted = response.status === 401;
          findings.push({
            id: `mendix-endpoint-${ep.path.replace(/\//g, '-')}`,
            title: `Mendix Endpoint ${isRestricted ? 'Exists (Auth Required)' : 'Accessible'}: ${ep.name}`,
            category: 'Mendix-Specific',
            severity: isRestricted ? 'info' : ep.severity,
            description: `${ep.description}. ${isRestricted ? 'Requires authentication.' : 'Accessible without authentication!'}`,
            evidence: `Path: ${ep.path}, Status: ${response.status}, Size: ${bodyLen} bytes`,
            remediation: isRestricted
              ? 'Authentication is enforced. Ensure strong credentials are used.'
              : `Restrict access to "${ep.path}". ${ep.severity === 'critical' ? 'This endpoint should NEVER be publicly accessible!' : 'Implement proper access controls.'}`,
            reference: 'https://docs.mendix.com/refguide/published-rest-services/'
          });
        }
      }
    } catch (err) {
      continue;
    }
  }

  // Phase 3: Test Mendix XAS endpoint for security
  try {
    const xasUrl = new URL(targetUrl);
    xasUrl.pathname = '/xas/';

    // Test XAS data retrieval without auth
    const xasResponse = await axios.post(xasUrl.toString(), {
      action: 'retrieve',
      params: {
        xpath: '//System.User',
        schema: { id: true, attributes: ['Name'] }
      }
    }, {
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'UniversalVAPTScanner/1.0',
        'Content-Type': 'application/json'
      }
    });

    if (xasResponse.status === 200 && xasResponse.data) {
      const data = typeof xasResponse.data === 'string' ? xasResponse.data : JSON.stringify(xasResponse.data);
      if (data.includes('objects') || data.includes('Name')) {
        findings.push({
          id: 'mendix-xas-user-enum',
          title: 'Mendix XAS: User Enumeration Possible',
          category: 'Mendix-Specific',
          severity: 'critical',
          description: 'The XAS endpoint allows retrieval of System.User entities without proper authentication. User data may be exposed.',
          evidence: `POST /xas/ with System.User xpath returned data`,
          remediation: 'Configure entity access rules to restrict System.User access. Ensure anonymous users cannot query user entities.',
          reference: 'https://docs.mendix.com/refguide/access-rules/'
        });
      }
    }

    // Test for anonymous session
    const sessionResponse = await axios.post(xasUrl.toString(), {
      action: 'get_session_data'
    }, {
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'UniversalVAPTScanner/1.0'
      }
    });

    if (sessionResponse.status === 200) {
      const sessionData = typeof sessionResponse.data === 'string' 
        ? sessionResponse.data 
        : JSON.stringify(sessionResponse.data);

      if (sessionData.includes('anonymous') || sessionData.includes('user')) {
        findings.push({
          id: 'mendix-anonymous-session',
          title: 'Mendix Anonymous Session Active',
          category: 'Mendix-Specific',
          severity: 'medium',
          description: 'Anonymous users can establish sessions with the Mendix runtime. Check what data and functionality is accessible to anonymous users.',
          evidence: `Session data returned for unauthenticated request`,
          remediation: 'Review anonymous user role permissions. Minimize data and page access for anonymous users.',
          reference: 'https://docs.mendix.com/refguide/anonymous-users/'
        });
      }
    }

  } catch (err) {
    // Skip
  }

  // Phase 4: Check for client-side security issues
  try {
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
    });

    if (typeof response.data === 'string') {
      const html = response.data;

      // Check for exposed Mendix client API
      if (/mx\.data\./i.test(html) || /mx\.session\./i.test(html)) {
        findings.push({
          id: 'mendix-client-api-exposed',
          title: 'Mendix Client API References in Source',
          category: 'Mendix-Specific',
          severity: 'info',
          description: 'The Mendix client API (mx.data, mx.session) is referenced in the page source. While normal for Mendix apps, ensure entity access rules properly restrict data access.',
          evidence: 'mx.data or mx.session references found in HTML',
          remediation: 'Ensure server-side entity access rules are properly configured. Client-side API access is controlled by server-side security.',
          reference: 'https://docs.mendix.com/refguide/access-rules/'
        });
      }

      // Check for exposed environment/configuration data
      const configPatterns = [
        { pattern: /database/i, name: 'Database Reference' },
        { pattern: /jdbc:/i, name: 'JDBC Connection String' },
        { pattern: /connection.?string/i, name: 'Connection String' },
        { pattern: /s3\.amazonaws/i, name: 'AWS S3 Reference' },
        { pattern: /blob\.core\.windows/i, name: 'Azure Blob Reference' },
      ];

      for (const cp of configPatterns) {
        if (cp.pattern.test(html)) {
          findings.push({
            id: `mendix-config-exposure-${cp.name.replace(/\s+/g, '-')}`,
            title: `Configuration Exposure: ${cp.name}`,
            category: 'Mendix-Specific',
            severity: 'medium',
            description: `Found ${cp.name} in the page source. This may reveal infrastructure details.`,
            evidence: `Pattern: ${cp.name} found in HTML`,
            remediation: 'Remove infrastructure references from client-side code. Use server-side constants.',
            reference: 'https://docs.mendix.com/refguide/constants/'
          });
        }
      }
    }
  } catch (err) {
    // Skip
  }

  // Phase 5: Check Mendix OData exposure
  try {
    const odataUrl = new URL(targetUrl);
    odataUrl.pathname = '/odata/';

    const response = await axios.get(odataUrl.toString(), {
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'UniversalVAPTScanner/1.0',
        'Accept': 'application/json'
      }
    });

    if (response.status === 200) {
      const data = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

      // Check for $metadata exposure
      const metadataUrl = new URL(targetUrl);
      metadataUrl.pathname = '/odata/v1/$metadata';

      const metaResp = await axios.get(metadataUrl.toString(), {
        timeout: 8000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'UniversalVAPTScanner/1.0' }
      });

      if (metaResp.status === 200) {
        findings.push({
          id: 'mendix-odata-metadata',
          title: 'Mendix OData $metadata Exposed',
          category: 'Mendix-Specific',
          severity: 'medium',
          description: 'The OData $metadata endpoint is accessible, revealing the full data model (entity names, attributes, relationships).',
          evidence: `GET /odata/v1/$metadata returned ${metaResp.status}`,
          remediation: 'Restrict $metadata access to authenticated users only. Review which entities are published via OData.',
          reference: 'https://docs.mendix.com/refguide/published-odata-services/'
        });
      }
    }
  } catch (err) {
    // Skip
  }

  return findings;
}

module.exports = { scan };
