// builds the harness page for p (d|b) and theme
const path = require("path");
const url = f => "file://" + f;
const JQUERY = url(require.resolve("jquery/dist/jquery.min.js", {paths: [__dirname, process.cwd()]}));
const HARNESS = url(path.join(__dirname, "harness.js"));
const CARD = url(path.join(__dirname, "..", "..", "TA-imperva-ioc-block", "appserver", "static", "imperva_form.js"));
module.exports = function (p, dark, extra) {
  const ipField = p === "b" ? "ip" : "src";
  const rows = [
    {ip: "54.245.10.21", inc: "ITHM 1000101", rule: "Threat - WAF scanner"},
    {ip: "54.245.88.7", inc: "ITHM 1000101", rule: "Threat - WAF scanner"},
    {ip: "198.51.100.23", inc: "ITHM 1000102", rule: "Risk - brute force"},
    {ip: "192.0.2.55", inc: "ITHM 1000103", rule: "Threat - IOC match"}];
  const tableId = p === "b" ? "b_table" : "det_table";
  const bg = dark ? "#171d21" : "#eef1f4", panel = dark ? "#212527" : "#ffffff", fg = dark ? "#fff" : "#000";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;background:${bg};color:${fg};font-family:Splunk Platform Sans,Helvetica,Arial,sans-serif}
.dashboard-row{display:flex;gap:8px;padding:4px 8px}.dashboard-cell{flex:1;min-width:0}.dashboard-panel{background:${panel};padding:8px 12px}
.fieldset{display:flex;gap:12px}.panel-title{font-size:16px;font-weight:400;margin:4px 0}table{border-collapse:collapse;width:100%}td,th{padding:4px 8px;border-bottom:1px solid #8884;text-align:left;font-size:12px}
.filler{height:1400px}</style>
<script src="${JQUERY}"></script>
<script>window.HARNESS=${JSON.stringify(Object.assign({p}, extra || {}))};window.ROWS=${JSON.stringify(rows)};</script>
<script src="${HARNESS}"></script></head><body>
<div class="dashboard-row"><div class="dashboard-cell"><div class="dashboard-panel">KPIs</div></div></div>
<div class="dashboard-row"><div id="${p}_actpanel" class="dashboard-cell"><div class="dashboard-panel">
  <h2 class="panel-title">Search and ${p === "b" ? "Unblock" : "Block"}</h2>
  <div class="fieldset"><div class="input">LEGACY INPUT q</div><div class="input">LEGACY INPUT tk</div></div>
  <div class="panel-element-row"><div id="${p}_acttable" class="dashboard-element table">LEGACY ACTION TABLE</div></div>
</div></div></div>
<div class="dashboard-row"><div class="dashboard-cell"><div class="dashboard-panel"><div id="${tableId}" class="dashboard-element table">
<table><thead><tr><th data-sort-key="${ipField}">${ipField}</th><th data-sort-key="VirusTotal">VirusTotal</th><th data-sort-key="incident_no">incident_no</th><th data-sort-key="severity">severity</th></tr></thead>
<tbody>${rows.map(r => `<tr><td>${r.ip}</td><td style="background-color:#2C62B3;color:#fff">🔗</td><td>${r.inc}</td><td>high</td></tr>`).join("")}</tbody></table>
</div></div></div></div>
<div class="filler"></div>
<script>$("#${tableId} tbody tr").on("click", function(){ rowClick($(this).children().eq(0).text(), $(this).children().eq(2).text()); });</script>
<script src="${CARD}"></script>
</body></html>`;
};
