// export-utils.js
// Universal Export Utility for IoT Security Auditor
// Supports exporting reports in JSON (.json), PDF (.pdf), and Word (.docx) formats

(function (global) {
  "use strict";

  // --- 1. ZIP Archive Builder in Pure JavaScript (No external dependencies) ---
  function createZip(files) {
    const fileEntries = [];
    let offset = 0;

    function crc32(buf) {
      let table = new Uint32Array(256);
      for (let i = 0; i < 256; i++) {
        let c = i;
        for (let k = 0; k < 8; k++) {
          c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        }
        table[i] = c;
      }
      let crc = -1;
      for (let i = 0; i < buf.length; i++) {
        crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff];
      }
      return (crc ^ -1) >>> 0;
    }

    const textEncoder = new TextEncoder();
    const chunks = [];

    for (const [name, content] of Object.entries(files)) {
      const nameBytes = textEncoder.encode(name);
      const contentBytes = typeof content === "string" ? textEncoder.encode(content) : content;
      const crc = crc32(contentBytes);
      const size = contentBytes.length;

      // Local file header (30 bytes + name length)
      const header = new Uint8Array(30 + nameBytes.length);
      const dv = new DataView(header.buffer);
      dv.setUint32(0, 0x04034b50, true); // Local file header signature
      dv.setUint16(4, 20, true); // Version needed to extract
      dv.setUint16(6, 0, true); // General purpose bit flag
      dv.setUint16(8, 0, true); // Compression method (0 = store)
      dv.setUint16(10, 0, true); // Last mod file time
      dv.setUint16(12, 0, true); // Last mod file date
      dv.setUint32(14, crc, true); // CRC-32
      dv.setUint32(18, size, true); // Compressed size
      dv.setUint32(22, size, true); // Uncompressed size
      dv.setUint16(26, nameBytes.length, true); // File name length
      dv.setUint16(28, 0, true); // Extra field length
      header.set(nameBytes, 30);

      fileEntries.push({
        nameBytes,
        crc,
        size,
        offset
      });

      chunks.push(header, contentBytes);
      offset += header.length + contentBytes.length;
    }

    const centralDirStart = offset;
    let centralDirSize = 0;

    for (const entry of fileEntries) {
      const cdHeader = new Uint8Array(46 + entry.nameBytes.length);
      const dv = new DataView(cdHeader.buffer);
      dv.setUint32(0, 0x02014b50, true); // Central directory signature
      dv.setUint16(4, 20, true); // Version made by
      dv.setUint16(6, 20, true); // Version needed to extract
      dv.setUint16(8, 0, true); // Bit flag
      dv.setUint16(10, 0, true); // Compression method
      dv.setUint16(12, 0, true); // Mod time
      dv.setUint16(14, 0, true); // Mod date
      dv.setUint32(16, entry.crc, true); // CRC-32
      dv.setUint32(20, entry.size, true); // Compressed size
      dv.setUint32(24, entry.size, true); // Uncompressed size
      dv.setUint16(28, entry.nameBytes.length, true); // File name length
      dv.setUint16(30, 0, true); // Extra field length
      dv.setUint16(32, 0, true); // File comment length
      dv.setUint16(34, 0, true); // Disk number start
      dv.setUint16(36, 0, true); // Internal file attributes
      dv.setUint32(38, 0, true); // External file attributes
      dv.setUint32(42, entry.offset, true); // Relative offset of local header
      cdHeader.set(entry.nameBytes, 46);

      chunks.push(cdHeader);
      centralDirSize += cdHeader.length;
      offset += cdHeader.length;
    }

    // End of central directory record (22 bytes)
    const eocd = new Uint8Array(22);
    const dv = new DataView(eocd.buffer);
    dv.setUint32(0, 0x06054b50, true); // EOCD signature
    dv.setUint16(4, 0, true); // Number of this disk
    dv.setUint16(6, 0, true); // Disk where central directory starts
    dv.setUint16(8, fileEntries.length, true); // Total entries on this disk
    dv.setUint16(10, fileEntries.length, true); // Total entries
    dv.setUint32(12, centralDirSize, true); // Size of central directory
    dv.setUint32(16, centralDirStart, true); // Offset of start of central directory
    dv.setUint16(20, 0, true); // Comment length

    chunks.push(eocd);

    const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
    const out = new Uint8Array(totalLength);
    let pos = 0;
    for (const chunk of chunks) {
      out.set(chunk, pos);
      pos += chunk.length;
    }
    return out;
  }

  // --- 2. Trigger Browser File Download ---
  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 150);
  }

  // --- 3. JSON Exporter ---
  function exportAuditAsJSON(reportData, customFilename) {
    const filename = customFilename || `iot-security-audit-${Date.now()}.json`;
    const jsonStr = JSON.stringify(reportData, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
    triggerDownload(blob, filename);
  }

  // --- 4. Pure Client-Side PDF Exporter (PDF 1.4 Binary Generator) ---
  function exportAuditAsPDF(reportData, customFilename) {
    const filename = customFilename || `iot-security-audit-${Date.now()}.pdf`;

    const objects = [];
    function addObject(content) {
      objects.push(content);
      return objects.length;
    }

    const fontRegObj = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    const fontBoldObj = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
    const fontMonoObj = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>");

    const pageWidth = 595.28;
    const pageHeight = 841.89;
    const margin = 40;
    const contentWidth = pageWidth - margin * 2;

    const pageContentsObjIds = [];
    let currentPageOps = [];
    let currentY = pageHeight - margin;

    function newPage() {
      if (currentPageOps.length > 0) {
        const streamData = currentPageOps.join("\n");
        const contObj = addObject(`<< /Length ${streamData.length} >>\nstream\n${streamData}\nendstream`);
        pageContentsObjIds.push(contObj);
        currentPageOps = [];
      }
      currentY = pageHeight - margin;
      drawPageHeader();
    }

    function checkSpace(needed) {
      if (currentY - needed < margin + 40) {
        newPage();
      }
    }

    function escapePdf(text) {
      if (text === undefined || text === null) return "";
      return String(text)
        .replace(/\\/g, "\\\\")
        .replace(/\(/g, "\\(")
        .replace(/\)/g, "\\)")
        .replace(/[\r\n]+/g, " ");
    }

    function drawPageHeader() {
      // Top header bar
      currentPageOps.push(`0.06 0.09 0.16 rg 0 ${pageHeight - 50} ${pageWidth} 50 re f`);
      currentPageOps.push(`BT /F2 14 Tf 1 1 1 rg ${margin} ${pageHeight - 32} Td (${escapePdf(reportData.title || "IoT Security Audit Dossier")}) Tj ET`);
      currentPageOps.push(`BT /F1 8 Tf 0.22 0.74 0.97 rg ${pageWidth - margin - 150} ${pageHeight - 32} Td (${escapePdf("XAI Diagnostic Suite")} ) Tj ET`);
      currentY = pageHeight - 70;
    }

    // First page top banner
    currentPageOps.push(`0.06 0.09 0.16 rg 0 ${pageHeight - 75} ${pageWidth} 75 re f`);
    currentPageOps.push(`BT /F2 17 Tf 1 1 1 rg ${margin} ${pageHeight - 38} Td (${escapePdf(reportData.title || "IoT Security Audit Dossier")}) Tj ET`);
    currentPageOps.push(`BT /F1 8.5 Tf 0.22 0.74 0.97 rg ${margin} ${pageHeight - 56} Td (${escapePdf("Generated: " + (reportData.timestamp || new Date().toLocaleString()) + " | Engine: Rust / Wasm Sandboxed Subsystem")}) Tj ET`);
    currentY = pageHeight - 95;

    // 1. Executive Summary Box
    checkSpace(110);
    currentPageOps.push(`0.92 0.95 0.98 rg ${margin} ${currentY - 90} ${contentWidth} 90 re f`);
    currentPageOps.push(`0.2 0.45 0.85 RG 1 w ${margin} ${currentY - 90} ${contentWidth} 90 re S`);

    currentPageOps.push(`BT /F2 11 Tf 0.06 0.09 0.16 rg ${margin + 12} ${currentY - 18} Td (${escapePdf("EXECUTIVE AUDIT SUMMARY")}) Tj ET`);

    const score = reportData.score !== undefined ? reportData.score : (reportData.overallPosture ? reportData.overallPosture.averageScore : 50);
    const scoreColor = score >= 80 ? "0.06 0.72 0.5" : score >= 50 ? "0.91 0.7 0.03" : "0.93 0.26 0.26";
    const postureRating = score >= 80 ? "Low Risk Posture (Hardened)" : score >= 50 ? "Moderate Risk Posture" : "High Risk Posture (Immediate Remediation)";

    currentPageOps.push(`BT /F2 10 Tf 0.3 0.35 0.45 rg ${margin + 12} ${currentY - 36} Td (${escapePdf("Overall Security Score:")}) Tj ET`);
    currentPageOps.push(`BT /F2 12 Tf ${scoreColor} rg ${margin + 150} ${currentY - 36} Td (${escapePdf(score + " / 100 (" + postureRating + ")")}) Tj ET`);

    if (reportData.targetUrl) {
      currentPageOps.push(`BT /F2 10 Tf 0.3 0.35 0.45 rg ${margin + 12} ${currentY - 52} Td (${escapePdf("Target Inspection URL:")}) Tj ET`);
      currentPageOps.push(`BT /F3 9 Tf 0.1 0.1 0.15 rg ${margin + 150} ${currentY - 52} Td (${escapePdf(reportData.targetUrl)}) Tj ET`);
    } else if (reportData.overallPosture) {
      currentPageOps.push(`BT /F2 10 Tf 0.3 0.35 0.45 rg ${margin + 12} ${currentY - 52} Td (${escapePdf("Monitored IoT Devices:")}) Tj ET`);
      currentPageOps.push(`BT /F1 9.5 Tf 0.1 0.1 0.15 rg ${margin + 150} ${currentY - 52} Td (${escapePdf(reportData.overallPosture.monitoredDevices + " Active Nodes (" + reportData.overallPosture.criticalFlaws + " Flaws Flagged)")}) Tj ET`);
    }

    if (reportData.counts) {
      currentPageOps.push(`BT /F2 9.5 Tf 0.3 0.35 0.45 rg ${margin + 12} ${currentY - 68} Td (${escapePdf("Severity Breakdown:")}) Tj ET`);
      currentPageOps.push(`BT /F1 9 Tf 0.93 0.26 0.26 rg ${margin + 150} ${currentY - 68} Td (${escapePdf("Critical: " + (reportData.counts.critical || 0))}) Tj ET`);
      currentPageOps.push(`BT /F1 9 Tf 0.97 0.45 0.08 rg ${margin + 225} ${currentY - 68} Td (${escapePdf("High: " + (reportData.counts.high || 0))}) Tj ET`);
      currentPageOps.push(`BT /F1 9 Tf 0.8 0.6 0.0 rg ${margin + 285} ${currentY - 68} Td (${escapePdf("Medium: " + (reportData.counts.medium || 0))}) Tj ET`);
      currentPageOps.push(`BT /F1 9 Tf 0.06 0.6 0.4 rg ${margin + 360} ${currentY - 68} Td (${escapePdf("Low: " + (reportData.counts.low || 0))}) Tj ET`);
    }

    currentY -= 110;

    // 2. Vulnerability Findings
    if (reportData.findings && reportData.findings.length > 0) {
      checkSpace(60);
      currentPageOps.push(`0.1 0.15 0.25 rg ${margin} ${currentY - 4} ${contentWidth} 18 re f`);
      currentPageOps.push(`BT /F2 10 Tf 1 1 1 rg ${margin + 8} ${currentY} Td (${escapePdf("DETECTED SECURITY FINDINGS & XAI EXPLANATIONS (" + reportData.findings.length + ")")}) Tj ET`);
      currentY -= 26;

      reportData.findings.forEach((f, idx) => {
        checkSpace(65);
        const fColor = f.severity === "critical" ? "0.93 0.26 0.26" : f.severity === "high" ? "0.97 0.45 0.08" : "0.91 0.7 0.03";
        currentPageOps.push(`0.97 0.98 0.99 rg ${margin} ${currentY - 44} ${contentWidth} 44 re f`);
        currentPageOps.push(`0.85 0.88 0.92 RG 0.5 w ${margin} ${currentY - 44} ${contentWidth} 44 re S`);
        currentPageOps.push(`${fColor} RG 3 w ${margin} ${currentY - 44} m ${margin} ${currentY} l S`);

        currentPageOps.push(`BT /F2 9.5 Tf ${fColor} rg ${margin + 10} ${currentY - 12} Td (${escapePdf("[" + (f.severity || "Risk").toUpperCase() + "] " + (f.type || "Finding #" + (idx + 1)))}) Tj ET`);
        currentPageOps.push(`BT /F1 8.5 Tf 0.2 0.2 0.25 rg ${margin + 10} ${currentY - 24} Td (${escapePdf("Detail: " + (f.detail || "") + (f.selector ? " (Element: " + f.selector + ")" : ""))}) Tj ET`);
        currentPageOps.push(`BT /F1 8 Tf 0.6 0.1 0.1 rg ${margin + 10} ${currentY - 36} Td (${escapePdf("Impact: " + (f.impact || "Vulnerability exploitation risk"))}) Tj ET`);
        currentY -= 52;

        if (f.shap && f.shap.length > 0) {
          checkSpace(18 + f.shap.length * 12);
          currentPageOps.push(`BT /F2 8 Tf 0.08 0.5 0.8 rg ${margin + 16} ${currentY} Td (${escapePdf("💡 SHAP Feature Attributions:")}) Tj ET`);
          currentY -= 12;
          f.shap.forEach(s => {
            currentPageOps.push(`BT /F1 7.5 Tf 0.3 0.35 0.4 rg ${margin + 24} ${currentY} Td (${escapePdf("• " + s.feature + "  ->  Weight: " + s.weight)}) Tj ET`);
            currentY -= 11;
          });
          currentY -= 4;
        }
      });
      currentY -= 10;
    }

    // 3. Transport & Defensive Headers Matrix
    if (reportData.headers) {
      checkSpace(90);
      currentPageOps.push(`0.1 0.15 0.25 rg ${margin} ${currentY - 4} ${contentWidth} 18 re f`);
      currentPageOps.push(`BT /F2 10 Tf 1 1 1 rg ${margin + 8} ${currentY} Td (${escapePdf("TRANSPORT & DEFENSIVE SECURITY HEADERS")}) Tj ET`);
      currentY -= 24;

      const headerItems = [
        ["HTTPS / TLS Enforced", reportData.headers.https],
        ["HTTP Strict Transport Security (HSTS)", reportData.headers.hsts],
        ["Content-Security-Policy (CSP)", reportData.headers.csp],
        ["X-Frame-Options (Clickjacking Defenses)", reportData.headers.xframe],
        ["Secure & HttpOnly Cookie Flags", reportData.headers.secureCookies]
      ];

      headerItems.forEach(([name, pass]) => {
        if (pass !== undefined) {
          checkSpace(16);
          const pColor = pass ? "0.06 0.72 0.5" : "0.93 0.26 0.26";
          const pText = pass ? "✓ PASSED (Enforced)" : "✕ FAILED (Missing or Insecure)";
          currentPageOps.push(`BT /F2 8.5 Tf 0.2 0.2 0.3 rg ${margin + 10} ${currentY} Td (${escapePdf(name + ":")}) Tj ET`);
          currentPageOps.push(`BT /F2 8.5 Tf ${pColor} rg ${margin + 240} ${currentY} Td (${escapePdf(pText)}) Tj ET`);
          currentY -= 14;
        }
      });
      currentY -= 12;
    }

    // 4. Device Inventory Table (if present)
    if (reportData.deviceInventory && reportData.deviceInventory.length > 0) {
      checkSpace(60);
      currentPageOps.push(`0.1 0.15 0.25 rg ${margin} ${currentY - 4} ${contentWidth} 18 re f`);
      currentPageOps.push(`BT /F2 10 Tf 1 1 1 rg ${margin + 8} ${currentY} Td (${escapePdf("DISCOVERED IOT DEVICE INVENTORY (" + reportData.deviceInventory.length + " NODES)")}) Tj ET`);
      currentY -= 22;

      // Table header
      currentPageOps.push(`0.88 0.91 0.95 rg ${margin} ${currentY - 2} ${contentWidth} 15 re f`);
      currentPageOps.push(`BT /F2 8 Tf 0.1 0.15 0.25 rg ${margin + 4} ${currentY + 2} Td (${escapePdf("Device Name")}) Tj ET`);
      currentPageOps.push(`BT /F2 8 Tf 0.1 0.15 0.25 rg ${margin + 140} ${currentY + 2} Td (${escapePdf("IP Address")}) Tj ET`);
      currentPageOps.push(`BT /F2 8 Tf 0.1 0.15 0.25 rg ${margin + 230} ${currentY + 2} Td (${escapePdf("Category")}) Tj ET`);
      currentPageOps.push(`BT /F2 8 Tf 0.1 0.15 0.25 rg ${margin + 310} ${currentY + 2} Td (${escapePdf("Risk Score")}) Tj ET`);
      currentPageOps.push(`BT /F2 8 Tf 0.1 0.15 0.25 rg ${margin + 370} ${currentY + 2} Td (${escapePdf("Identified Flaws")}) Tj ET`);
      currentY -= 16;

      reportData.deviceInventory.forEach((d, i) => {
        checkSpace(18);
        if (i % 2 === 1) {
          currentPageOps.push(`0.97 0.98 0.99 rg ${margin} ${currentY - 3} ${contentWidth} 14 re f`);
        }
        currentPageOps.push(`0.88 0.9 0.93 RG 0.4 w ${margin} ${currentY - 3} ${contentWidth} 14 re S`);

        const dScoreColor = d.score >= 80 ? "0.06 0.72 0.5" : d.score >= 50 ? "0.91 0.7 0.03" : "0.93 0.26 0.26";
        currentPageOps.push(`BT /F2 7.5 Tf 0.1 0.1 0.1 rg ${margin + 4} ${currentY} Td (${escapePdf(d.name.slice(0, 24))}) Tj ET`);
        currentPageOps.push(`BT /F3 7.5 Tf 0.2 0.2 0.3 rg ${margin + 140} ${currentY} Td (${escapePdf(d.ip)}) Tj ET`);
        currentPageOps.push(`BT /F1 7.5 Tf 0.3 0.3 0.4 rg ${margin + 230} ${currentY} Td (${escapePdf(d.category || "IoT")}) Tj ET`);
        currentPageOps.push(`BT /F2 7.5 Tf ${dScoreColor} rg ${margin + 310} ${currentY} Td (${escapePdf(d.score + "/100")}) Tj ET`);
        const flawsStr = (d.flaws && d.flaws.length) ? d.flaws.join(", ").slice(0, 30) : "No High Flaws";
        currentPageOps.push(`BT /F1 7 Tf 0.4 0.4 0.45 rg ${margin + 370} ${currentY} Td (${escapePdf(flawsStr)}) Tj ET`);
        currentY -= 14;
      });
      currentY -= 12;
    }

    // Push final page stream
    if (currentPageOps.length > 0) {
      const streamData = currentPageOps.join("\n");
      const contObj = addObject(`<< /Length ${streamData.length} >>\nstream\n${streamData}\nendstream`);
      pageContentsObjIds.push(contObj);
    }

    // Pages catalog assembly
    const pagesObjIndex = addObject("");
    const createdPageObjIds = [];
    for (let i = 0; i < pageContentsObjIds.length; i++) {
      const pObj = addObject(`<< /Type /Page /Parent ${pagesObjIndex} 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 ${fontRegObj} 0 R /F2 ${fontBoldObj} 0 R /F3 ${fontMonoObj} 0 R >> >> /Contents ${pageContentsObjIds[i]} 0 R >>`);
      createdPageObjIds.push(pObj);
    }
    objects[pagesObjIndex - 1] = `<< /Type /Pages /Kids [${createdPageObjIds.map(id => id + " 0 R").join(" ")}] /Count ${createdPageObjIds.length} >>`;

    const catalogObjIndex = addObject(`<< /Type /Catalog /Pages ${pagesObjIndex} 0 R >>`);

    // Compile PDF
    let pdf = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
    const offsets = [];
    for (let i = 0; i < objects.length; i++) {
      offsets.push(pdf.length);
      pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
    }
    const xrefOffset = pdf.length;
    pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const off of offsets) {
      pdf += String(off).padStart(10, "0") + " 00000 n \n";
    }
    pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogObjIndex} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

    const buf = new Uint8Array(pdf.length);
    for (let i = 0; i < pdf.length; i++) {
      buf[i] = pdf.charCodeAt(i) & 0xff;
    }
    const blob = new Blob([buf], { type: "application/pdf" });
    triggerDownload(blob, filename);
  }

  // --- 5. Pure Client-Side Word (.docx) Exporter ---
  function exportAuditAsDOCX(reportData, customFilename) {
    const filename = customFilename || `iot-security-audit-${Date.now()}.docx`;

    function xmlEscape(str) {
      if (str === undefined || str === null) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
    }

    let body = "";

    // Document Title
    body += `
      <w:p>
        <w:pPr>
          <w:jc w:val="left"/>
          <w:spacing w:before="240" w:after="100"/>
        </w:pPr>
        <w:r>
          <w:rPr>
            <w:b/>
            <w:sz w:val="44"/>
            <w:color w:val="0F172A"/>
          </w:rPr>
          <w:t>${xmlEscape(reportData.title || "IoT Security Auditor - Executive Report")}</w:t>
        </w:r>
      </w:p>
      <w:p>
        <w:pPr>
          <w:spacing w:after="300"/>
        </w:pPr>
        <w:r>
          <w:rPr>
            <w:sz w:val="20"/>
            <w:color w:val="64748B"/>
          </w:rPr>
          <w:t>Generated: ${xmlEscape(reportData.timestamp || new Date().toLocaleString())} | Engine: Rust / Wasm Native Subsystem (Manifest V3)</w:t>
        </w:r>
      </w:p>
    `;

    // 1. Executive Summary Table
    const score = reportData.score !== undefined ? reportData.score : (reportData.overallPosture ? reportData.overallPosture.averageScore : 50);
    const postureRating = score >= 80 ? "Low Risk Posture (Hardened)" : score >= 50 ? "Moderate Risk Posture" : "High Risk Posture (Immediate Remediation Required)";
    const scoreColor = score >= 80 ? "10B981" : score >= 50 ? "EAB308" : "EF4444";

    body += `
      <w:p>
        <w:pPr><w:spacing w:before="200" w:after="100"/></w:pPr>
        <w:r>
          <w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="1E293B"/></w:rPr>
          <w:t>1. Executive Summary &amp; Posture Assessment</w:t>
        </w:r>
      </w:p>
      <w:tbl>
        <w:tblPr>
          <w:tblW w:w="9200" w:type="dxa"/>
          <w:tblBorders>
            <w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
            <w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
            <w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>
            <w:left w:val="none"/><w:right w:val="none"/><w:insideV w:val="none"/>
          </w:tblBorders>
        </w:tblPr>
        <w:tr>
          <w:tc><w:tcPr><w:tcW w:w="3400" w:type="dxa"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:sz w:val="20"/><w:color w:val="334155"/></w:rPr><w:t>Security Posture Score:</w:t></w:r></w:p></w:tc>
          <w:tc><w:tcPr><w:tcW w:w="5800" w:type="dxa"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:sz w:val="22"/><w:color w:val="${scoreColor}"/></w:rPr><w:t>${xmlEscape(score + " / 100 — " + postureRating)}</w:t></w:r></w:p></w:tc>
        </w:tr>
    `;

    if (reportData.targetUrl) {
      body += `
        <w:tr>
          <w:tc><w:p><w:r><w:rPr><w:b/><w:sz w:val="20"/><w:color w:val="334155"/></w:rPr><w:t>Audited Target URL:</w:t></w:r></w:p></w:tc>
          <w:tc><w:p><w:r><w:rPr><w:sz w:val="20"/><w:color w:val="0369A1"/></w:rPr><w:t>${xmlEscape(reportData.targetUrl)}</w:t></w:r></w:p></w:tc>
        </w:tr>
      `;
    }

    if (reportData.counts) {
      body += `
        <w:tr>
          <w:tc><w:p><w:r><w:rPr><w:b/><w:sz w:val="20"/><w:color w:val="334155"/></w:rPr><w:t>Vulnerability Counts:</w:t></w:r></w:p></w:tc>
          <w:tc><w:p><w:r><w:rPr><w:sz w:val="20"/></w:rPr><w:t>Critical: ${reportData.counts.critical || 0}, High: ${reportData.counts.high || 0}, Medium: ${reportData.counts.medium || 0}, Low: ${reportData.counts.low || 0}</w:t></w:r></w:p></w:tc>
        </w:tr>
      `;
    }

    if (reportData.overallPosture) {
      body += `
        <w:tr>
          <w:tc><w:p><w:r><w:rPr><w:b/><w:sz w:val="20"/><w:color w:val="334155"/></w:rPr><w:t>Monitored Devices:</w:t></w:r></w:p></w:tc>
          <w:tc><w:p><w:r><w:rPr><w:sz w:val="20"/></w:rPr><w:t>${reportData.overallPosture.monitoredDevices} local IoT nodes (${reportData.overallPosture.criticalFlaws} total vulnerabilities flagged)</w:t></w:r></w:p></w:tc>
        </w:tr>
      `;
    }

    body += `</w:tbl>`;

    // 2. Vulnerability Findings List
    if (reportData.findings && reportData.findings.length > 0) {
      body += `
        <w:p>
          <w:pPr><w:spacing w:before="360" w:after="100"/></w:pPr>
          <w:r>
            <w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="1E293B"/></w:rPr>
            <w:t>2. Detected Vulnerabilities &amp; Explainable AI (SHAP)</w:t>
          </w:r>
        </w:p>
      `;

      reportData.findings.forEach((f, idx) => {
        const sevColor = f.severity === "critical" ? "EF4444" : f.severity === "high" ? "F97316" : f.severity === "medium" ? "EAB308" : "10B981";
        body += `
          <w:p>
            <w:pPr><w:spacing w:before="160" w:after="40"/></w:pPr>
            <w:r>
              <w:rPr><w:b/><w:sz w:val="22"/><w:color w:val="${sevColor}"/></w:rPr>
              <w:t>[${xmlEscape(String(f.severity || "Risk").toUpperCase())}] ${xmlEscape(f.type || f.title || "Vulnerability #" + (idx + 1))}</w:t>
            </w:r>
          </w:p>
          <w:p>
            <w:pPr><w:spacing w:after="40"/></w:pPr>
            <w:r>
              <w:rPr><w:sz w:val="20"/><w:color w:val="334155"/></w:rPr>
              <w:t>Detail: ${xmlEscape(f.detail || "")} ${xmlEscape(f.selector ? "(Element: " + f.selector + ")" : "")}</w:t>
            </w:r>
          </w:p>
          <w:p>
            <w:pPr><w:spacing w:after="60"/></w:pPr>
            <w:r>
              <w:rPr><w:i/><w:sz w:val="20"/><w:color w:val="991B1B"/></w:rPr>
              <w:t>Impact: ${xmlEscape(f.impact || "Exploitable weakness")}</w:t>
            </w:r>
          </w:p>
        `;

        if (f.shap && f.shap.length > 0) {
          body += `
            <w:p>
              <w:pPr><w:spacing w:after="20"/></w:pPr>
              <w:r><w:rPr><w:b/><w:sz w:val="18"/><w:color w:val="0284C7"/></w:rPr><w:t>  Explainable AI (SHAP) Feature Attribution:</w:t></w:r>
            </w:p>
          `;
          f.shap.forEach(s => {
            body += `
              <w:p>
                <w:pPr><w:ind w:left="400"/><w:spacing w:after="20"/></w:pPr>
                <w:r><w:rPr><w:sz w:val="18"/><w:color w:val="475569"/></w:rPr><w:t>• ${xmlEscape(s.feature)}: </w:t></w:r>
                <w:r><w:rPr><w:b/><w:sz w:val="18"/><w:color w:val="D97706"/></w:rPr><w:t>${xmlEscape(String(s.weight))}</w:t></w:r>
              </w:p>
            `;
          });
        }
      });
    }

    // 3. Defensive Headers Matrix
    if (reportData.headers) {
      body += `
        <w:p>
          <w:pPr><w:spacing w:before="360" w:after="100"/></w:pPr>
          <w:r>
            <w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="1E293B"/></w:rPr>
            <w:t>3. Transport &amp; Defensive Header Verification</w:t>
          </w:r>
        </w:p>
        <w:tbl>
          <w:tblPr>
            <w:tblW w:w="9200" w:type="dxa"/>
            <w:tblBorders>
              <w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
              <w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
              <w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>
              <w:left w:val="none"/><w:right w:val="none"/><w:insideV w:val="none"/>
            </w:tblBorders>
          </w:tblPr>
      `;

      const headerMap = {
        "HTTPS / TLS Enforced": reportData.headers.https,
        "HTTP Strict Transport Security (HSTS)": reportData.headers.hsts,
        "Content-Security-Policy (CSP)": reportData.headers.csp,
        "X-Frame-Options (Clickjacking Protection)": reportData.headers.xframe,
        "Secure & HttpOnly Cookie Flags": reportData.headers.secureCookies
      };

      for (const [hName, hPass] of Object.entries(headerMap)) {
        if (hPass !== undefined) {
          body += `
            <w:tr>
              <w:tc><w:tcPr><w:tcW w:w="5000" w:type="dxa"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:sz w:val="20"/><w:color w:val="334155"/></w:rPr><w:t>${xmlEscape(hName)}</w:t></w:r></w:p></w:tc>
              <w:tc><w:tcPr><w:tcW w:w="4200" w:type="dxa"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:color w:val="${hPass ? "10B981" : "EF4444"}"/><w:sz w:val="20"/></w:rPr><w:t>${hPass ? "✓ PASSED (Enforced)" : "✕ FAILED (Missing or Insecure)"}</w:t></w:r></w:p></w:tc>
            </w:tr>
          `;
        }
      }
      body += `</w:tbl>`;
    }

    // 4. Device Inventory Table (for dashboard reports)
    if (reportData.deviceInventory && reportData.deviceInventory.length > 0) {
      body += `
        <w:p>
          <w:pPr><w:spacing w:before="360" w:after="100"/></w:pPr>
          <w:r>
            <w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="1E293B"/></w:rPr>
            <w:t>4. Connected IoT Device Inventory</w:t>
          </w:r>
        </w:p>
        <w:tbl>
          <w:tblPr>
            <w:tblW w:w="9200" w:type="dxa"/>
            <w:tblBorders>
              <w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
              <w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
              <w:left w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
              <w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
              <w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>
              <w:insideV w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>
            </w:tblBorders>
          </w:tblPr>
          <w:tr>
            <w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="0F172A"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="18"/></w:rPr><w:t>Device Name</w:t></w:r></w:p></w:tc>
            <w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="0F172A"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="18"/></w:rPr><w:t>IP Address</w:t></w:r></w:p></w:tc>
            <w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="0F172A"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="18"/></w:rPr><w:t>Category</w:t></w:r></w:p></w:tc>
            <w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="0F172A"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="18"/></w:rPr><w:t>Score</w:t></w:r></w:p></w:tc>
            <w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="0F172A"/></w:tcPr><w:p><w:r><w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="18"/></w:rPr><w:t>Identified Flaws</w:t></w:r></w:p></w:tc>
          </w:tr>
      `;

      reportData.deviceInventory.forEach(d => {
        body += `
          <w:tr>
            <w:tc><w:p><w:r><w:rPr><w:b/><w:sz w:val="18"/></w:rPr><w:t>${xmlEscape(d.name)}</w:t></w:r></w:p></w:tc>
            <w:tc><w:p><w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t>${xmlEscape(d.ip)}</w:t></w:r></w:p></w:tc>
            <w:tc><w:p><w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t>${xmlEscape(d.category || "IoT")}</w:t></w:r></w:p></w:tc>
            <w:tc><w:p><w:r><w:rPr><w:b/><w:sz w:val="18"/></w:rPr><w:t>${xmlEscape(String(d.score))}/100</w:t></w:r></w:p></w:tc>
            <w:tc><w:p><w:r><w:rPr><w:sz w:val="18"/></w:rPr><w:t>${xmlEscape((d.flaws && d.flaws.join("; ")) || "None")}</w:t></w:r></w:p></w:tc>
          </w:tr>
        `;
      });
      body += `</w:tbl>`;
    }

    const docxXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    ${body}
  </w:body>
</w:document>`;

    const docxZip = createZip({
      "[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`,
      "_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
      "word/document.xml": docxXml
    });

    const blob = new Blob([docxZip], { type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" });
    triggerDownload(blob, filename);
  }

  // --- 6. Export by Format Dispatcher ---
  function exportAuditReport(format, reportData, filenameBase) {
    const stamp = Date.now();
    const base = filenameBase || "iot-security-audit";
    switch (format.toLowerCase()) {
      case "pdf":
        exportAuditAsPDF(reportData, `${base}-${stamp}.pdf`);
        break;
      case "docx":
        exportAuditAsDOCX(reportData, `${base}-${stamp}.docx`);
        break;
      case "json":
      default:
        exportAuditAsJSON(reportData, `${base}-${stamp}.json`);
        break;
    }
  }

  // Expose to global window and module.exports
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      IoTReportExporter: {
        exportAuditReport,
        exportAuditAsJSON,
        exportAuditAsPDF,
        exportAuditAsDOCX
      }
    };
  }
  global.IoTReportExporter = {
    exportAuditReport,
    exportAuditAsJSON,
    exportAuditAsPDF,
    exportAuditAsDOCX
  };

})(typeof window !== "undefined" ? window : globalThis);
