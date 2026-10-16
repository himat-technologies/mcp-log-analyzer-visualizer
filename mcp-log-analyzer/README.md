# MCP Log Analyzer & Tracing Visualizer

[✨ Try the live demo](https://himat.tech/free-tools/mcp-log-analyzer-visualizer)

## Project overview

This lightweight browser tool helps developers inspect local Model Context Protocol (MCP) logs. It parses common stdio, JSON-RPC, and Server-Sent Events (SSE) entries, checks basic JSON-RPC structure, pairs requests with responses, and makes common secret values safer to share.

## Features

- Paste logs or locally select `.log`, `.txt`, and `.json` files.
- Parse timestamped stdio lines, individual and multiline JSON, JSON-RPC batches, and basic SSE `data:` events.
- Validate JSON-RPC 2.0 requests, notifications, responses, IDs, and error objects, with readable diagnostics.
- Match request and response IDs, identify unmatched or duplicate IDs, and show measured latency in a simple waterfall.
- Calculate average latency only from timestamped `tools/call` cycles.
- Filter frames by level, message type, and method name.
- Detect and redact common API keys, GitHub tokens, bearer tokens, passwords, cloud keys, and database URLs with credentials.
- Copy or download the sanitized raw stream.
- Try the three included sample traces.

## Technologies

HTML, CSS, and vanilla JavaScript. There are no runtime libraries or build tools.

## Requirements

A modern browser and a local computer. No API keys, database, backend, or Node.js installation is required.

## How to run locally

### Option 1: Open directly

1. Download or clone the repository.
2. Open `mcp-log-analyzer/index.html` in a modern browser.
3. Paste logs or load a sample, then click **Analyze Logs**.

The sample buttons work when opening the page directly. The sample files are also included in `samples/` for inspection or editing.

### Option 2: Open with npm on Windows

From the repository root, run:

```bash
npm run dev
```

This opens the app in your default browser. The npm script has no package dependencies and does not start a backend.

### Option 3: Run a local development server

Open a terminal in the `mcp-log-analyzer` project directory and run:

```bash
python -m http.server 8000
```

Open `http://localhost:8000` in your browser. On Windows, `py -m http.server 8000` is also commonly available. If starting from the repository root, use:

```powershell
py -m http.server 8000 --directory .\mcp-log-analyzer
```

This server only serves static files. It does not parse, receive, or upload log data.

## How to use

1. Paste a log into the input area, upload a `.log`, `.txt`, or `.json` file, or choose one of the sample buttons.
2. Click **Analyze Logs**. Parsing, validation, and secret redaction happen locally in the browser.
3. Review the summary cards and protocol diagnostics. Expand a frame to inspect its sanitized JSON or original sanitized log line.
4. Use the latency waterfall to review request-response cycles. Latency is shown only when both timestamps are available and ordered.
5. Filter by log level, message type, or a method substring; filters apply immediately.
6. Copy or download the sanitized raw stream when you need to share it.

## Privacy

Log analysis runs in the browser. The page has no backend, external API calls, analytics, or third-party runtime resources, and it does not store logs in browser storage. File contents are read locally and are not uploaded. Clicking **Clear** removes the input and in-memory results.

Secret detection is pattern based. It covers common credential formats but cannot guarantee detection of every secret, so review the sanitized output before sharing.

## Limitations

MCP log formats vary between clients and transports, so unusual wrappers may need manual inspection. Incomplete logs, missing timestamps, or unmatched requests can prevent latency calculation. The JSON-RPC checks are basic protocol checks and are not a complete MCP conformance test. Time-only timestamps have no date; their latency is measured within a single day.

## License

This repository includes an MIT license in the root `LICENSE` file.

## 💜 Himat Technologies

**Himat Technologies — AI-first software development company**

- 🌐 Website: [himat.co.in](https://himat.co.in)
- 📘 Facebook: [Himat Technologies](https://www.facebook.com/people/Himat-technologies/61593829197445/)
- 💼 LinkedIn: [Himat Technologies](https://www.linkedin.com/in/himat-technologies-14b1051b4)
- 📸 Instagram: [@himat_technologies](https://www.instagram.com/himat_technologies?stkn=djdmcGxweWtwYWI0)
- ✉️ Email: [info@himat.co.in](mailto:info@himat.co.in)
- ☎️ Contact: [94452 34023](tel:9445234023)
- ✨ Demo: [MCP Log Analyzer & Tracing Visualizer](https://himat.tech/free-tools/mcp-log-analyzer-visualizer)
