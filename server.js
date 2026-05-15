const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { runFullScan } = require('./scanners');

// Prevent immediate close on crash
process.on('uncaughtException', (err) => {
  console.error('\n[FATAL ERROR]', err.message);
  console.error(err.stack);
  console.log('\nPress any key to exit...');
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on('data', process.exit.bind(process, 1));
});

process.on('unhandledRejection', (reason) => {
  console.error('\n[UNHANDLED REJECTION]', reason);
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
  maxHttpBufferSize: 5e6
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory scan storage
const scans = new Map();

// REST API: Start a new scan
app.post('/api/scan', async (req, res) => {
  const { targetUrl, modules, options } = req.body;

  if (!targetUrl) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  // Validate URL
  try {
    new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const scanId = crypto.randomUUID();
  const scan = {
    id: scanId,
    targetUrl,
    modules: modules || 'all',
    options: options || {},
    status: 'running',
    startedAt: new Date().toISOString(),
    completedAt: null,
    findings: [],
    summary: null,
    progress: 0,
    techStack: 'Unknown'
  };

  scans.set(scanId, scan);

  res.json({ scanId, status: 'started' });

  // Run scan asynchronously
  try {
    await runFullScan(scan, (event) => {
      // Broadcast progress to all connected clients
      io.emit(`scan:${scanId}`, event);

      if (event.type === 'finding') {
        scan.findings.push(event.data);
      }
      if (event.type === 'progress') {
        scan.progress = event.data.percent;
      }
      if (event.type === 'module_complete') {
        // Update findings from the module
        if (event.data.findings) {
          scan.findings.push(...event.data.findings);
        }
      }
    });

    scan.status = 'completed';
    scan.completedAt = new Date().toISOString();
    scan.summary = generateSummary(scan);
    io.emit(`scan:${scanId}`, { type: 'complete', data: scan.summary });
  } catch (err) {
    scan.status = 'error';
    scan.error = err.message;
    scan.completedAt = new Date().toISOString();
    io.emit(`scan:${scanId}`, { type: 'error', data: { message: err.message } });
  }
});

// REST API: Get scan status/results
app.get('/api/scan/:scanId', (req, res) => {
  const scan = scans.get(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  res.json(scan);
});

// REST API: Ignore finding
app.post('/api/scan/:scanId/ignore', (req, res) => {
  const scan = scans.get(req.params.scanId);
  if (!scan) {
    // Graceful fallback if server restarted and memory was cleared
    console.warn(`Scan ${req.params.scanId} not found in memory (server restarted). Simulating success.`);
    return res.json({ success: true, summary: { riskScore: 0, severityCounts: {}, categoryCounts: {} } });
  }

  const { findingId, ignored } = req.body;
  const finding = scan.findings.find(f => f.id === findingId);
  if (finding) {
    finding.ignored = ignored;
  }
  
  scan.summary = generateSummary(scan);
  res.json({ success: true, summary: scan.summary });
});

// REST API: Get all scans
app.get('/api/scans', (req, res) => {
  const allScans = Array.from(scans.values()).map(s => ({
    id: s.id,
    targetUrl: s.targetUrl,
    status: s.status,
    startedAt: s.startedAt,
    completedAt: s.completedAt,
    findingsCount: s.findings.length,
    summary: s.summary,
    techStack: s.techStack
  }));
  res.json(allScans);
});

// Generate plain text replication steps for exports
function generateReplicationStepsPlain(finding, targetUrl) {
  const cat = (finding.category || '').toLowerCase();
  const evidence = finding.evidence || '';
  const url = targetUrl || 'http://localhost:8080';
  
  if (cat.includes('header') || cat.includes('cookie') || cat.includes('cors')) {
    return `1. Open your terminal or command prompt.\n2. Run the following command: curl -I -k "${url}"\n3. Inspect the response headers to verify the missing or misconfigured attribute shown in the evidence.`;
  }
  if (cat.includes('xss') || cat.includes('injection') || cat.includes('sqli')) {
    return `1. Navigate to the vulnerable endpoint or parameter.\n2. Inject the specific payload shown in the Evidence section: ${evidence.substring(0, 80)}\n3. Submit the request and observe the response (look for script execution, database errors, or bypasses).`;
  }
  if (cat.includes('mendix')) {
    return `1. Open your browser DevTools (F12) -> Network tab.\n2. Reload the Mendix application and filter by XHR/Fetch.\n3. Locate the Mendix API call (e.g., /xas/ or /p/) and inspect the request/response payloads to verify the misconfiguration.`;
  }
  if (cat.includes('csrf') || cat.includes('ssrf')) {
    return `1. Open Postman (or Burp Suite) and create a new HTTP request targeting the affected endpoint.\n2. Set the HTTP method to POST/PUT/DELETE as required.\n3. Remove or intentionally modify the Anti-CSRF token in the headers/body.\n4. Send the request and check if it processes successfully (200 OK).`;
  }
  return `1. Setup: Open Postman and create a new HTTP request to the affected URL.\n2. Configure Request: Set the HTTP method and add any specific headers/parameters exactly as they appear in the Evidence section.\n3. Execute: Send the request to the server.\n4. Analyze Response: Inspect the response body and HTTP status code. The vulnerability is confirmed if the server leaks sensitive data or behaves unexpectedly.`;
}

// REST API: Export scan report as JSON
app.get('/api/scan/:scanId/export', (req, res) => {
  const scan = scans.get(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  const activeFindings = scan.findings.filter(f => !f.ignored).map(f => ({
    ...f,
    replicationSteps: generateReplicationStepsPlain(f, scan.targetUrl)
  }));

  const report = {
    reportId: crypto.randomUUID(),
    generatedAt: new Date().toISOString(),
    tool: 'Universal VAPT Scanner v1.0.0',
    target: scan.targetUrl,
    scanDuration: scan.completedAt
      ? `${((new Date(scan.completedAt) - new Date(scan.startedAt)) / 1000).toFixed(1)}s`
      : 'In Progress',
    summary: scan.summary,
    findings: activeFindings,
    disclaimer: 'This scan was performed for authorized security assessment purposes only. Results should be validated manually by a qualified security professional. Some findings may have been marked as false positives and excluded from this report.'
  };

  res.setHeader('Content-Disposition', `attachment; filename=vapt-report-${scan.id.slice(0, 8)}.json`);
  res.setHeader('Content-Type', 'application/json');
  res.json(report);
});

// REST API: Export scan report as Excel
app.get('/api/scan/:scanId/export-excel', async (req, res) => {
  const scan = scans.get(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  try {
    const ExcelJS = require('exceljs');
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'Universal VAPT Scanner';
    workbook.created = new Date();

    // Color palette
    const colors = {
      critical: { bg: 'FFFFE0E6', text: 'FFDC2626', border: 'FFFCA5A5' },
      high:     { bg: 'FFFFF3E0', text: 'FFEA580C', border: 'FFFED7AA' },
      medium:   { bg: 'FFFFFDE7', text: 'FFCA8A04', border: 'FFFEF08A' },
      low:      { bg: 'FFE0F7FA', text: 'FF0891B2', border: 'FFA5F3FC' },
      info:     { bg: 'FFF3F4F6', text: 'FF6B7280', border: 'FFD1D5DB' },
      header:   { bg: 'FF1E293B', text: 'FFFFFFFF' },
      accent:   { bg: 'FF0EA5E9', text: 'FFFFFFFF' },
      white:    'FFFFFFFF',
      lightGray: 'FFF8FAFC',
    };

    const severityOrder = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
    const activeFindings = scan.findings.filter(f => !f.ignored);
    const sortedFindings = [...activeFindings].sort((a, b) =>
      (severityOrder[a.severity] || 6) - (severityOrder[b.severity] || 6)
    );
    const scanDuration = scan.completedAt
      ? `${((new Date(scan.completedAt) - new Date(scan.startedAt)) / 1000).toFixed(1)} seconds`
      : 'In Progress';

    // ========== SHEET 1: EXECUTIVE SUMMARY ==========
    const summarySheet = workbook.addWorksheet('Executive Summary', {
      properties: { tabColor: { argb: '0EA5E9' } }
    });
    summarySheet.columns = [
      { width: 25 }, { width: 20 }, { width: 15 }, { width: 15 }, { width: 50 }
    ];

    // Title
    summarySheet.mergeCells('A1:E1');
    const titleCell = summarySheet.getCell('A1');
    titleCell.value = 'UNIVERSAL VAPT SECURITY ASSESSMENT REPORT';
    titleCell.font = { name: 'Calibri', size: 18, bold: true, color: { argb: colors.header.text } };
    titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.header.bg } };
    titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
    summarySheet.getRow(1).height = 45;

    // Subtitle
    summarySheet.mergeCells('A2:E2');
    const subCell = summarySheet.getCell('A2');
    subCell.value = 'Generated by Universal VAPT Scanner v1.0.0';
    subCell.font = { name: 'Calibri', size: 10, italic: true, color: { argb: 'FF94A3B8' } };
    subCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.header.bg } };
    subCell.alignment = { horizontal: 'center' };

    // Scan details
    const details = [
      ['Target URL', scan.targetUrl],
      ['Detected Tech Stack', scan.techStack],
      ['Scan Date', new Date(scan.startedAt).toLocaleString()],
      ['Duration', scanDuration],
      ['Status', scan.status.toUpperCase()],
      ['Total Active Findings', activeFindings.length.toString()],
      ['Risk Score', `${scan.summary?.riskScore || 0} / 100 (${scan.summary?.riskLevel || 'N/A'})`],
    ];

    let row = 4;
    details.forEach(([label, value]) => {
      const labelCell = summarySheet.getCell(`A${row}`);
      labelCell.value = label;
      labelCell.font = { name: 'Calibri', size: 11, bold: true, color: { argb: 'FF334155' } };
      summarySheet.mergeCells(`B${row}:E${row}`);
      const valCell = summarySheet.getCell(`B${row}`);
      valCell.value = value;
      valCell.font = { name: 'Calibri', size: 11, color: { argb: 'FF475569' } };
      row++;
    });

    // Severity breakdown table
    row += 1;
    summarySheet.mergeCells(`A${row}:E${row}`);
    const sevTitle = summarySheet.getCell(`A${row}`);
    sevTitle.value = 'SEVERITY BREAKDOWN';
    sevTitle.font = { name: 'Calibri', size: 13, bold: true, color: { argb: colors.header.text } };
    sevTitle.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.header.bg } };
    sevTitle.alignment = { horizontal: 'center' };
    summarySheet.getRow(row).height = 30;
    row++;

    const sevHeaders = ['Severity', 'Count', 'Priority', 'Action Required', 'Description'];
    sevHeaders.forEach((h, i) => {
      const cell = summarySheet.getCell(row, i + 1);
      cell.value = h;
      cell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: colors.accent.text } };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.accent.bg } };
      cell.alignment = { horizontal: 'center' };
    });
    row++;

    const sevData = [
      ['CRITICAL', scan.summary?.severityCounts?.critical || 0, 'P1 - Immediate', 'Fix within 24 hours', 'Exploitable vulnerabilities that can lead to full system compromise'],
      ['HIGH', scan.summary?.severityCounts?.high || 0, 'P2 - Urgent', 'Fix within 1 week', 'Serious vulnerabilities requiring prompt attention'],
      ['MEDIUM', scan.summary?.severityCounts?.medium || 0, 'P3 - Important', 'Fix within 1 month', 'Moderate risk issues to address in next sprint'],
      ['LOW', scan.summary?.severityCounts?.low || 0, 'P4 - Minor', 'Fix when convenient', 'Low-risk issues, best practice recommendations'],
      ['INFO', scan.summary?.severityCounts?.info || 0, 'P5 - Informational', 'Review only', 'Informational findings for awareness'],
    ];

    sevData.forEach(([sev, count, priority, action, desc]) => {
      const sevKey = sev.toLowerCase();
      const c = colors[sevKey];
      [sev, count, priority, action, desc].forEach((val, i) => {
        const cell = summarySheet.getCell(row, i + 1);
        cell.value = val;
        cell.font = { name: 'Calibri', size: 10, bold: i === 0, color: { argb: i === 0 ? c.text : 'FF334155' } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: c.bg } };
        cell.alignment = { horizontal: i === 1 ? 'center' : 'left', vertical: 'middle', wrapText: true };
        cell.border = {
          top: { style: 'thin', color: { argb: c.border } },
          bottom: { style: 'thin', color: { argb: c.border } },
        };
      });
      row++;
    });

    // Category breakdown
    row += 1;
    summarySheet.mergeCells(`A${row}:E${row}`);
    const catTitle = summarySheet.getCell(`A${row}`);
    catTitle.value = 'FINDINGS BY CATEGORY';
    catTitle.font = { name: 'Calibri', size: 13, bold: true, color: { argb: colors.header.text } };
    catTitle.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.header.bg } };
    catTitle.alignment = { horizontal: 'center' };
    summarySheet.getRow(row).height = 30;
    row++;

    if (scan.summary?.categoryCounts) {
      const sorted = Object.entries(scan.summary.categoryCounts).sort((a, b) => b[1] - a[1]);
      ['Category', 'Findings Count'].forEach((h, i) => {
        const cell = summarySheet.getCell(row, i + 1);
        cell.value = h;
        cell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: colors.accent.text } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.accent.bg } };
      });
      row++;
      sorted.forEach(([cat, count], idx) => {
        const bgColor = idx % 2 === 0 ? colors.white : colors.lightGray;
        summarySheet.getCell(row, 1).value = cat;
        summarySheet.getCell(row, 1).font = { name: 'Calibri', size: 10 };
        summarySheet.getCell(row, 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: bgColor } };
        summarySheet.getCell(row, 2).value = count;
        summarySheet.getCell(row, 2).font = { name: 'Calibri', size: 10, bold: true };
        summarySheet.getCell(row, 2).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: bgColor } };
        summarySheet.getCell(row, 2).alignment = { horizontal: 'center' };
        row++;
      });
    }

    // Disclaimer
    row += 1;
    summarySheet.mergeCells(`A${row}:E${row}`);
    const discCell = summarySheet.getCell(`A${row}`);
    discCell.value = '⚠ DISCLAIMER: This scan was performed for authorized security assessment purposes only. Results should be validated manually by a qualified security professional. Some findings may have been marked as false positives and excluded from this report.';
    discCell.font = { name: 'Calibri', size: 9, italic: true, color: { argb: 'FFCA8A04' } };
    discCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFFDE7' } };
    discCell.alignment = { wrapText: true };
    summarySheet.getRow(row).height = 35;

    // ========== SHEET 2: ALL FINDINGS ==========
    const findingsSheet = workbook.addWorksheet('All Findings', {
      properties: { tabColor: { argb: 'DC2626' } }
    });

    const fCols = [
      { header: '#', key: 'num', width: 5 },
      { header: 'Severity', key: 'severity', width: 12 },
      { header: 'Priority', key: 'priority', width: 16 },
      { header: 'Category', key: 'category', width: 22 },
      { header: 'Title', key: 'title', width: 40 },
      { header: 'Description', key: 'description', width: 55 },
      { header: 'Evidence', key: 'evidence', width: 45 },
      { header: 'How to Replicate', key: 'replication', width: 55 },
      { header: 'How to Fix', key: 'remediation', width: 55 },
      { header: 'OWASP Reference', key: 'reference', width: 35 },
    ];
    findingsSheet.columns = fCols;

    // Style header row
    const headerRow = findingsSheet.getRow(1);
    headerRow.height = 30;
    headerRow.eachCell((cell) => {
      cell.font = { name: 'Calibri', size: 11, bold: true, color: { argb: colors.header.text } };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.header.bg } };
      cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
      cell.border = {
        bottom: { style: 'medium', color: { argb: 'FF0EA5E9' } }
      };
    });

    // Add autofilter
    findingsSheet.autoFilter = { from: 'A1', to: 'J1' };

    // Priority mapping
    const priorityMap = {
      critical: 'P1 - Immediate',
      high: 'P2 - Urgent',
      medium: 'P3 - Important',
      low: 'P4 - Minor',
      info: 'P5 - Informational'
    };

    // Add findings data
    sortedFindings.forEach((f, idx) => {
      const r = findingsSheet.addRow({
        num: idx + 1,
        severity: f.severity.toUpperCase(),
        priority: priorityMap[f.severity] || 'P5',
        category: f.category,
        title: f.title,
        description: f.description,
        evidence: f.evidence,
        replication: generateReplicationStepsPlain(f, scan.targetUrl),
        remediation: f.remediation,
        reference: f.reference || '',
      });

      const c = colors[f.severity] || colors.info;
      r.height = 45;
      r.eachCell((cell, colNum) => {
        cell.font = { name: 'Calibri', size: 10, color: { argb: 'FF334155' } };
        cell.alignment = { vertical: 'top', wrapText: true };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: idx % 2 === 0 ? colors.white : colors.lightGray } };
        cell.border = {
          bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } }
        };

        // Color-code severity column
        if (colNum === 2) {
          cell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: c.text } };
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: c.bg } };
          cell.alignment = { horizontal: 'center', vertical: 'top' };
        }
        // Color-code priority column
        if (colNum === 3) {
          cell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: c.text } };
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: c.bg } };
        }
        // Monospace for evidence
        if (colNum === 7) {
          cell.font = { name: 'Consolas', size: 9, color: { argb: 'FF0EA5E9' } };
        }
        // Style Replication Steps
        if (colNum === 8) {
          cell.font = { name: 'Calibri', size: 10, color: { argb: 'FF64748B' } };
        }
        // Bold remediation
        if (colNum === 9) {
          cell.font = { name: 'Calibri', size: 10, color: { argb: 'FF166534' } };
        }
      });
    });

    // Freeze top row
    findingsSheet.views = [{ state: 'frozen', ySplit: 1 }];

    // ========== SHEET 3: PRIORITY ACTION PLAN ==========
    const planSheet = workbook.addWorksheet('Priority Action Plan', {
      properties: { tabColor: { argb: '16A34A' } }
    });
    planSheet.columns = [
      { header: 'Priority', key: 'priority', width: 18 },
      { header: 'Severity', key: 'severity', width: 12 },
      { header: 'Issue', key: 'title', width: 40 },
      { header: 'Category', key: 'category', width: 22 },
      { header: 'Fix Action', key: 'fix', width: 60 },
      { header: 'Timeline', key: 'timeline', width: 18 },
      { header: 'Status', key: 'status', width: 14 },
    ];

    const planHeader = planSheet.getRow(1);
    planHeader.height = 30;
    planHeader.eachCell((cell) => {
      cell.font = { name: 'Calibri', size: 11, bold: true, color: { argb: colors.header.text } };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: colors.header.bg } };
      cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    });

    planSheet.autoFilter = { from: 'A1', to: 'G1' };

    const timelineMap = {
      critical: 'Within 24 hours',
      high: 'Within 1 week',
      medium: 'Within 1 month',
      low: 'Next quarter',
      info: 'When convenient'
    };

    sortedFindings.forEach((f, idx) => {
      const c = colors[f.severity] || colors.info;
      const r = planSheet.addRow({
        priority: priorityMap[f.severity] || 'P5',
        severity: f.severity.toUpperCase(),
        title: f.title,
        category: f.category,
        fix: f.remediation,
        timeline: timelineMap[f.severity] || 'When convenient',
        status: '☐ Open',
      });

      r.height = 40;
      r.eachCell((cell, colNum) => {
        cell.font = { name: 'Calibri', size: 10, color: { argb: 'FF334155' } };
        cell.alignment = { vertical: 'top', wrapText: true };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: idx % 2 === 0 ? colors.white : colors.lightGray } };
        cell.border = { bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } } };

        if (colNum === 1 || colNum === 2) {
          cell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: c.text } };
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: c.bg } };
          cell.alignment = { horizontal: 'center', vertical: 'top' };
        }
        if (colNum === 5) {
          cell.font = { name: 'Calibri', size: 10, color: { argb: 'FF166534' } };
        }
        if (colNum === 7) {
          cell.font = { name: 'Calibri', size: 10, bold: true, color: { argb: 'FFCA8A04' } };
          cell.alignment = { horizontal: 'center', vertical: 'top' };
        }
      });
    });

    planSheet.views = [{ state: 'frozen', ySplit: 1 }];

    // Write to response
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=VAPT-Report-${scan.id.slice(0, 8)}-${new Date().toISOString().slice(0, 10)}.xlsx`);

    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error('Excel export error:', err);
    res.status(500).json({ error: 'Failed to generate Excel report: ' + err.message });
  }
});

// Socket.IO connection
io.on('connection', (socket) => {
  console.log(`[WS] Client connected: ${socket.id}`);
  socket.on('disconnect', () => {
    console.log(`[WS] Client disconnected: ${socket.id}`);
  });
});

function generateSummary(scan) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categoryMap = {};

  let totalFindings = 0;

  for (const finding of scan.findings) {
    if (finding.ignored) continue;

    totalFindings++;
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
    if (!categoryMap[finding.category]) {
      categoryMap[finding.category] = [];
    }
    categoryMap[finding.category].push(finding);
  }

  // Calculate risk score (0-100)
  const riskScore = Math.min(100, 
    severityCounts.critical * 25 + 
    severityCounts.high * 15 + 
    severityCounts.medium * 8 + 
    severityCounts.low * 3 + 
    severityCounts.info * 1
  );

  let riskLevel = 'Low';
  if (riskScore >= 75) riskLevel = 'Critical';
  else if (riskScore >= 50) riskLevel = 'High';
  else if (riskScore >= 25) riskLevel = 'Medium';

  return {
    totalFindings,
    severityCounts,
    riskScore,
    riskLevel,
    techStack: scan.techStack,
    categoryCounts: Object.fromEntries(
      Object.entries(categoryMap).map(([k, v]) => [k, v.length])
    )
  };
}

// Serve the dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════════════╗`);
  console.log(`║     Universal VAPT Scanner v1.0.0                   ║`);
  console.log(`║     Security Assessment Tool                     ║`);
  console.log(`╠══════════════════════════════════════════════════╣`);
  console.log(`║  Dashboard: http://localhost:${PORT}                 ║`);
  console.log(`║  API:       http://localhost:${PORT}/api              ║`);
  console.log(`╚══════════════════════════════════════════════════╝\n`);

  // Auto-open browser on Windows
  if (process.platform === 'win32') {
    exec(`start http://localhost:${PORT}`);
  }
});
