import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import analytics

HTML_PAGE = """<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>OQOS Analytics Dashboard</title>
    <style>
      :root { color-scheme: dark; }
      body { font-family: Arial, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
      .wrap { max-width: 1200px; margin: 32px auto; padding: 0 16px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }
      .card { background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 16px; }
      .label { color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
      .value { font-size: 2rem; margin-top: 8px; font-weight: 700; }
      table { width: 100%; border-collapse: collapse; margin-top: 24px; }
      th, td { border-bottom: 1px solid #334155; padding: 10px; text-align: left; }
      code { background: #0b1120; border: 1px solid #334155; padding: 2px 6px; border-radius: 6px; }
      .muted { color: #94a3b8; }
    </style>
  </head>
  <body>
    <div class=\"wrap\">
      <h1>OQOS Analytics Dashboard</h1>
      <p class=\"muted\">Live harvest view for signed and unsigned request activity.</p>
      <div class=\"grid\" id=\"stats\"></div>
      <h2>Per-agent summary</h2>
      <div id=\"agent-table\"></div>
      <h2>Tag distribution</h2>
      <div id=\"tag-distribution\"></div>
    </div>
    <script>
      async function loadSummary() {
        const res = await fetch('/api/summary');
        const data = await res.json();
        const stats = [
          ['Total sightings', data.total_sightings],
          ['Unique agents', data.unique_agents],
          ['Unsigned', data.unsigned_count],
          ['Verification rate', `${(data.verification_rate * 100).toFixed(1)}%`],
          ['Replay attempts', data.replay_attempts],
        ];
        document.getElementById('stats').innerHTML = stats.map(([label, value]) => `
          <div class=\"card\">
            <div class=\"label\">${label}</div>
            <div class=\"value\">${value}</div>
          </div>
        `).join('');

        const agentRows = data.per_agent_summary.length ? data.per_agent_summary.map(row => `
          <tr>
            <td><code>${row.keyid.slice(0, 16)}...</code></td>
            <td>${row.n_requests}</td>
            <td>${row.n_verified}</td>
            <td>${row.tags || '—'}</td>
            <td>${row.paths_hit || '—'}</td>
          </tr>
        `).join('') : '<p class=\"muted\">No attributable agents recorded yet.</p>';
        document.getElementById('agent-table').innerHTML = `
          <table>
            <thead><tr><th>Agent</th><th>Requests</th><th>Verified</th><th>Tags</th><th>Paths</th></tr></thead>
            <tbody>${agentRows}</tbody>
          </table>
        `;

        const tagEntries = Object.entries(data.tag_distribution);
        document.getElementById('tag-distribution').innerHTML = tagEntries.length ? `
          <table>
            <thead><tr><th>Tag</th><th>Count</th></tr></thead>
            <tbody>${tagEntries.map(([tag, count]) => `<tr><td>${tag}</td><td>${count}</td></tr>`).join('')}</tbody>
          </table>
        ` : '<p class=\"muted\">No tags recorded yet.</p>';
      }
      loadSummary();
      setInterval(loadSummary, 5000);
    </script>
  </body>
</html>
"""


def _build_summary():
    analytics.init_db()
    return {
        "total_sightings": analytics.total_sightings(),
        "unique_agents": analytics.unique_agents(),
        "unsigned_count": analytics.unsigned_count(),
        "verification_rate": analytics.verification_rate(),
        "replay_attempts": analytics.replay_attempts(),
        "tag_distribution": analytics.tag_distribution(),
        "per_agent_summary": analytics.per_agent_summary(),
        "distinct_keyids_per_remote_addr": analytics.distinct_keyids_per_remote_addr(),
    }


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode())
            return

        if path == "/api/summary":
            payload = json.dumps(_build_summary()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/api/health":
            payload = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        return


def main(host: str = "127.0.0.1", port: int = 8000):
    analytics.init_db()
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard available at http://{host}:{port}")
    print(f"Summary API available at http://{host}:{port}/api/summary")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
