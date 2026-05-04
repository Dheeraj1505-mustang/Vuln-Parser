const express = require("express");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());

// Serve frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const SCAN_TYPE_MAP = {
  "1": "quick",
  "2": "xss",
  "3": "full"
};

app.post("/scan", (req, res) => {
  const { target, scanType } = req.body;

  if (!target || !scanType) {
    return res.json({ error: "Target or scan type missing" });
  }

  const cleanTarget = target
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "")
    .trim();

  if (!/^[a-zA-Z0-9.\-_:]+$/.test(cleanTarget)) {
    return res.json({ error: "Invalid target format" });
  }

  const mappedScanType = SCAN_TYPE_MAP[scanType] || "quick";
  const pythonScript = path.join(__dirname, "web.py");
  const pythonBin = "/home/thigu/vuln_parser/venv/bin/python3";

  // Construct report paths directly — no need to parse stdout
  const htmlReportPath = path.join(__dirname, cleanTarget, `${cleanTarget}_report.html`);
  const jsonReportPath = path.join(__dirname, cleanTarget, `${cleanTarget}_report.json`);

  let allOutput = "";

  const proc = spawn(pythonBin, [pythonScript, cleanTarget, mappedScanType], {
    cwd: __dirname
  });

  proc.stdout.on("data", (data) => { allOutput += data.toString(); });
  proc.stderr.on("data", (data) => { allOutput += data.toString(); });

  proc.on("close", (code) => {
    if (fs.existsSync(htmlReportPath)) {
      return res.json({ htmlReport: fs.readFileSync(htmlReportPath, "utf8") });
    }
    if (fs.existsSync(jsonReportPath)) {
      return res.json({ textReport: fs.readFileSync(jsonReportPath, "utf8") });
    }
    return res.json({ textReport: allOutput || "Scan finished but no report found." });
  });

  proc.on("error", (err) => {
    return res.json({ error: "Failed to start scan: " + err.message });
  });
});

app.listen(5000, () => {
  console.log("✅ VulnParser server running at http://localhost:5000");
});
