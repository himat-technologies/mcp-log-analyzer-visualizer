# 🧭 MCP Log Analyzer & Tracing Visualizer

**Turn raw MCP logs into clear, useful traces — privately, right in your browser.**

[✨ Open the live demo](https://himat.tech/free-tools/mcp-log-analyzer-visualizer) · [📬 Contact Himat Technologies](mailto:info@himat.co.in)

Paste or upload MCP logs to inspect JSON-RPC messages, spot protocol issues, measure tool latency, and redact common credentials before sharing. Everything is processed locally in your browser.

## 🌈 What you can do

| Feature | Description |
| --- | --- |
| 🧾 Parse logs | Inspect stdio, JSON-RPC, JSON batches, and basic SSE events. |
| 📊 See the overview | Review frame counts, valid messages, tool latency, and redacted secrets. |
| 🔎 Find protocol issues | Check JSON-RPC structure and surface malformed or unmatched messages. |
| ⏱️ Trace requests | Match request/response IDs and visualize timestamped latency. |
| 🛡️ Share more safely | Detect and redact common credentials, then copy or download sanitized logs. |
| 🧪 Try sample traces | Explore filesystem, protocol-error, and SSE examples. |

## 🚀 Run locally

The app uses plain HTML, CSS, and JavaScript. There are no npm dependencies or backend services.

On Windows, run this from the repository root:

```powershell
npm run dev
```

This opens `mcp-log-analyzer/index.html` in your default browser. You can also open that file directly, or serve the static files with Python:

```powershell
py -m http.server 8000 --directory .\mcp-log-analyzer
```

Then visit [http://localhost:8000](http://localhost:8000).

## 🔐 Privacy

Log parsing and redaction happen in the browser. The app does not upload logs or require an account, API key, or server. Secret detection is pattern based; review sanitized output before sharing because unknown credential formats may not be recognized.

## 💜 Made by Himat Technologies

| Connect | Link |
| --- | --- |
| 🌐 Website | [himat.co.in](https://himat.co.in) |
| 📘 Facebook | [Himat Technologies](https://www.facebook.com/people/Himat-technologies/61593829197445/) |
| 💼 LinkedIn | [Himat Technologies](https://www.linkedin.com/in/himat-technologies-14b1051b4) |
| 📸 Instagram | [@himat_technologies](https://www.instagram.com/himat_technologies?stkn=djdmcGxweWtwYWI0) |
| ✉️ Email | [info@himat.co.in](mailto:info@himat.co.in) |
| ☎️ Contact | [94452 34023](tel:9445234023) |

---

Built with care by [Himat Technologies](https://himat.co.in).
