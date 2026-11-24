from html import escape
from collections import Counter
from datetime import datetime, timezone
from forensic_core import analyze_events

def generate_html_report(events, path, case_name, case_id, hashes=None, errors=None):
    hashes, errors = hashes or {}, errors or []
    analysis = analyze_events(events)
    counts, browsers = analysis["artifact_counts"], analysis["browser_counts"]
    def cell(value): return escape(str(value if value is not None else ""))
    def table_rows(rows, keys):
        return "".join("<tr>" + "".join(f"<td>{cell(row.get(k,''))}</td>" for k in keys) + "</tr>" for row in rows)
    timeline = sorted(events, key=lambda x:x.get("timestamp",""), reverse=True)
    suspicious = analysis["suspicious"]
    correlations = analysis["correlations"]
    duplicate_rows = analysis["duplicates"]
    cards = [("Total artifacts",len(events))] + [(k,v) for k,v in counts.items()]
    cards_html = "".join(f'<div class="card"><strong>{v:,}</strong><span>{cell(k)}</span></div>' for k,v in cards)
    browser_html = "".join(f'<div class="barrow"><span>{cell(k)}</span><div class="bar"><i style="width:{(v/max(browsers.values())*100 if browsers else 0):.1f}%"></i></div><b>{v:,}</b></div>' for k,v in browsers.items())
    timeline_rows = table_rows(timeline, ["timestamp","browser","artifact_type","title","url","details","source_file"])
    suspicious_rows = table_rows(suspicious, ["timestamp","browser","title","url","reasons"])
    correlation_rows = table_rows(correlations, ["url","browsers","count","first_seen","last_seen"])
    hash_rows = "".join(f"<tr><td>{cell(k)}</td><td><code>{cell(v)}</code></td></tr>" for k,v in hashes.items())
    error_html = "".join(f"<li>{cell(e)}</li>" for e in errors) or "<li>No extraction errors were recorded.</li>"
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebForensix Investigation Report</title>
<style>
:root{{--navy:#17324d;--blue:#2563a6;--pale:#eef4fa;--line:#d6e0ea;--ink:#263746;--muted:#617386}}
*{{box-sizing:border-box}}body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f7fa;color:var(--ink);line-height:1.45}}
header{{background:linear-gradient(120deg,#132b43,#24577e);color:#fff;padding:34px max(24px,calc((100% - 1400px)/2))}}
header h1{{margin:0 0 8px;font-size:30px}}header p{{margin:0;color:#dce8f3}}
main{{max-width:1400px;margin:24px auto;padding:0 24px}}.meta,.panel{{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 2px 8px #18344d0a}}
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}}.meta b{{color:var(--navy)}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin:18px 0 22px}}
.card{{background:white;border:1px solid var(--line);border-radius:12px;padding:18px}}.card strong{{display:block;font-size:27px;color:var(--navy)}}.card span{{color:var(--muted);font-size:13px}}
h2{{font-size:21px;color:var(--navy);margin:0 0 15px}}h3{{font-size:16px;color:var(--navy)}}
.barrow{{display:grid;grid-template-columns:100px 1fr 60px;gap:12px;align-items:center;margin:10px 0}}.bar{{height:12px;background:#e7edf4;border-radius:20px;overflow:hidden}}.bar i{{display:block;height:100%;background:linear-gradient(90deg,#2b6da8,#63a5d2);border-radius:20px}}
.table-wrap{{overflow-x:auto;max-height:650px;border:1px solid var(--line);border-radius:8px}}
table{{border-collapse:collapse;width:100%;font-size:12px;table-layout:auto;background:#fff}}th,td{{border-bottom:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere;min-width:95px}}
th{{background:#eaf1f7;color:#203b54;position:sticky;top:0;z-index:1}}td:nth-child(1){{min-width:190px;white-space:nowrap}}td:nth-child(2),td:nth-child(3){{min-width:90px}}td:nth-child(5){{min-width:280px;max-width:520px}}td:last-child{{min-width:180px}}
.note{{background:#fff8e8;border-left:4px solid #d6a23d;padding:12px 15px;border-radius:4px}}.muted{{color:var(--muted)}}code{{overflow-wrap:anywhere}}footer{{text-align:center;color:var(--muted);font-size:12px;padding:25px}}
@media print{{body{{background:white}}main{{max-width:none;margin:0;padding:0 10px}}.panel,.meta{{box-shadow:none;break-inside:avoid}}.table-wrap{{max-height:none;overflow:visible}}th{{position:static}}header{{padding:20px}}}}
</style></head><body>
<header><h1>Cross-Browser Digital Forensic Artifact Analyzer</h1><p>WebForensix · Digital browser evidence investigation report</p></header>
<main>
<section class="meta"><div class="meta-grid">
<div><b>Case name:</b> {cell(case_name)}</div><div><b>Case ID:</b> {cell(case_id)}</div>
<div><b>Generated (UTC):</b> {datetime.now(timezone.utc).isoformat(timespec="seconds")}</div>
<div><b>Total artifacts:</b> {len(events):,}</div></div></section>
<section class="cards">{cards_html}</section>
<section class="panel"><h2>Artifacts by browser</h2>{browser_html or '<p class="muted">No browser artifacts available.</p>'}</section>
<section class="panel"><h2>URL review indicators</h2>
<p class="note">These are rule-based review indicators only. They do not establish that a URL is malicious. Validate every finding with context and additional evidence.</p>
<p><b>Flagged records:</b> {len(suspicious):,}</p>
<div class="table-wrap"><table><thead><tr><th>Timestamp (UTC)</th><th>Browser</th><th>Title</th><th>URL</th><th>Reason for review</th></tr></thead><tbody>{suspicious_rows or '<tr><td colspan="5">No URLs matched the configured review rules.</td></tr>'}</tbody></table></div></section>
<section class="panel"><h2>Cross-browser URL correlations</h2>
<p class="muted">Identical normalized URLs observed in more than one browser. This indicates shared URL activity, not necessarily the same person or a causal relationship.</p>
<div class="table-wrap"><table><thead><tr><th>Normalized URL</th><th>Browsers</th><th>Occurrences</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>{correlation_rows or '<tr><td colspan="5">No cross-browser URL matches were found.</td></tr>'}</tbody></table></div></section>
<section class="panel"><h2>Potential duplicate records</h2><p>Exact duplicate key: browser, artifact type, title, normalized URL, and timestamp.</p><p><b>Potential duplicates:</b> {len(duplicate_rows):,}</p></section>
<section class="panel"><h2>Unified chronological timeline</h2><div class="table-wrap"><table><thead><tr><th>Timestamp (UTC)</th><th>Browser</th><th>Type</th><th>Title / Name</th><th>URL / Domain</th><th>Details</th><th>Source evidence</th></tr></thead><tbody>{timeline_rows or '<tr><td colspan="7">No artifacts extracted.</td></tr>'}</tbody></table></div></section>
<section class="panel"><h2>Evidence SHA-256 hashes</h2><div class="table-wrap"><table><thead><tr><th>Evidence database</th><th>SHA-256</th></tr></thead><tbody>{hash_rows or '<tr><td colspan="2">No evidence hashes recorded.</td></tr>'}</tbody></table></div></section>
<section class="panel"><h2>Extraction messages</h2><ul>{error_html}</ul></section>
<section class="panel"><h2>Methodology, interpretation and limitations</h2>
<ul><li>Browser SQLite databases are read through temporary SQLite backup snapshots where supported.</li>
<li>Event timestamps are normalized to UTC. Browser-native timestamps and schema differences can affect availability.</li>
<li>Cookie values and passwords are not collected; only cookie metadata is included.</li>
<li>Search terms are inferred from query parameters in visited search-engine URLs.</li>
<li>URL review indicators are heuristic triage signals, not malware detection or a definitive maliciousness verdict.</li>
<li>Cross-browser correlations match normalized URLs across browser records; they do not prove user identity or intent.</li>
<li>Missing artifacts do not prove that an activity did not occur. Browser versions, profile state, locks, encryption and retention settings may affect extraction.</li></ul>
<p class="note"><b>Forensic caution:</b> Use verified forensic copies where possible, preserve originals, document acquisition and chain of custody, and manually validate significant findings before drawing conclusions.</p>
</section>
</main><footer>Generated by WebForensix · Academic forensic triage prototype</footer></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
