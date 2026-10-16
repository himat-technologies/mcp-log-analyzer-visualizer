// The parser only receives sanitized text. Original credentials never reach render().
const KNOWN_METHODS = new Set([
  'initialize',
  'notifications/initialized',
  'tools/list',
  'tools/call',
  'resources/list',
  'resources/read',
  'prompts/list',
  'prompts/get',
  'ping',
  'logging/setLevel',
  'completion/complete',
  'sampling/createMessage',
  'elicitation/create',
  'roots/list',
  'notifications/cancelled',
  'notifications/progress',
  'notifications/message',
]);

const ERROR_CODE_NAMES = {
  '-32700': 'Parse error',
  '-32600': 'Invalid Request',
  '-32601': 'Method not found',
  '-32602': 'Invalid params',
  '-32603': 'Internal error',
};

const SENSITIVE_PATTERNS = [
  {
    placeholder: 'DATABASE_URL',
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/gi,
    replace(value) {
      const punctuation = value.match(/[),.;]+$/)?.[0] || '';
      const url = punctuation ? value.slice(0, -punctuation.length) : value;
      const authority = url.slice(url.indexOf('://') + 3).split('/')[0];
      return /[^:@]+:[^@]+@/.test(authority)
        ? `[REDACTED_DATABASE_URL]${punctuation}`
        : value;
    },
  },
  {
    placeholder: 'BEARER_TOKEN',
    pattern: /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi,
  },
  {
    placeholder: 'GITHUB_TOKEN',
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  },
  {
    placeholder: 'API_KEY',
    pattern: /\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{30,})\b/g,
  },
  {
    placeholder: 'CLOUD_ACCESS_KEY',
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  },
];

const CREDENTIAL_ASSIGNMENT = /((?:["']?)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|google[_-]?api[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?secret|secret[_-]?key|secret|password|passwd|pwd|private[_-]?key|credential|authorization|auth|token)(?:["']?)\s*[:=]\s*)(?:"([^"]*)"|'([^']*)'|(\[REDACTED_[A-Z_]+\])|([^\s"',;}\]]+))/gi;

function placeholderForCredential(keyText) {
  const key = keyText.toLowerCase();
  if (key.includes('api') && key.includes('key')) return 'API_KEY';
  if (key.includes('token')) return 'ACCESS_TOKEN';
  if (key.includes('password') || key.includes('passwd') || key.includes('pwd')) return 'PASSWORD';
  if (key.includes('access_key_id')) return 'CLOUD_ACCESS_KEY';
  if (key.includes('aws')) return 'CLOUD_SECRET_KEY';
  return 'SECRET';
}

function redactSecrets(text) {
  let sanitized = String(text);
  let count = 0;

  for (const rule of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(rule.pattern, value => {
      const replacement = rule.replace ? rule.replace(value) : `[REDACTED_${rule.placeholder}]`;
      if (replacement !== value) count += 1;
      return replacement;
    });
  }

  sanitized = sanitized.replace(CREDENTIAL_ASSIGNMENT, (match, prefix, doubleQuoted, singleQuoted, existingPlaceholder, plainValue) => {
    const value = doubleQuoted ?? singleQuoted ?? plainValue ?? '';
    if (existingPlaceholder || !value || /^\[REDACTED_[A-Z_]+\]$/.test(value)) return match;

    const placeholder = placeholderForCredential(prefix);
    const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
    count += 1;
    return `${prefix}${quote}[REDACTED_${placeholder}]${quote}`;
  });

  return { text: sanitized, count };
}

function parseTimestamp(text) {
  const match = String(text).match(/\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b/);
  if (!match) return null;

  const value = match[1];
  if (value.includes('-')) {
    const isoValue = value.replace(' ', 'T');
    const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/.test(isoValue);
    const parsed = Date.parse(hasTimezone ? isoValue : `${isoValue}Z`);
    return Number.isNaN(parsed) ? null : parsed;
  }

  const [hours, minutes, secondsAndMs] = value.split(':');
  const [seconds, milliseconds = '0'] = secondsAndMs.split('.');
  const ms = Number((milliseconds + '00').slice(0, 3));
  return Date.UTC(2000, 0, 1, Number(hours), Number(minutes), Number(seconds), ms);
}

function findTimestampText(text) {
  return String(text).match(/\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b/)?.[1] || '';
}

function findJsonStart(text) {
  let offset = 0;
  let remaining = String(text);
  const prefixes = [
    /^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*/i,
    /^\s*\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*/,
    /^\s*\[(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2}|TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)[^\]]*\]\s*/i,
    /^\s*(?:TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)\s*:?\s*/i,
    /^\s*stdio\s+(?:rx|tx):\s*/i,
    /^\s*data:\s*/i,
  ];
  while (true) {
    const prefixMatch = prefixes.map(pattern => remaining.match(pattern)).find(Boolean);
    if (!prefixMatch) break;
    offset += prefixMatch[0].length;
    remaining = remaining.slice(prefixMatch[0].length);
  }

  const objectStart = remaining.indexOf('{');
  const arrayStart = remaining.indexOf('[');
  if (objectStart < 0) return arrayStart < 0 ? -1 : offset + arrayStart;
  if (arrayStart < 0) return offset + objectStart;
  return offset + Math.min(objectStart, arrayStart);
}

function parseJsonPayload(text) {
  const withoutSseMetadata = String(text)
    .split(/\r?\n/)
    .filter(line => !/^\s*(?:event|id|retry):/i.test(line) && !/^\s*:/i.test(line))
    .map(line => line.replace(/^\s*data:\s*/i, ''))
    .join('\n');
  const start = findJsonStart(withoutSseMetadata);
  if (start < 0) return { found: false, value: null, error: null };

  const candidate = withoutSseMetadata.slice(start).trim();
  try {
    return { found: true, value: JSON.parse(candidate), error: null };
  } catch (error) {
    const startsWithJson = /^[\s]*[\[{]/.test(withoutSseMetadata);
    const hasLogPrefix = /(?:stdio\s+(?:rx|tx):|^\s*data:)/im.test(text);
    const hasTimestampPrefix = /^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(text);
    const hasJsonRpcFields = /"(?:jsonrpc|method|id|result|error)"\s*:/.test(candidate);
    if (!startsWithJson && !hasLogPrefix && !hasTimestampPrefix && !hasJsonRpcFields) {
      return { found: false, value: null, error: null };
    }
    return { found: true, value: null, error };
  }
}

function hasBalancedJson(text) {
  const start = findJsonStart(text);
  if (start < 0) return false;

  const opening = text[start];
  const closing = opening === '{' ? '}' : ']';
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let index = start; index < text.length; index += 1) {
    const character = text[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === opening) depth += 1;
    else if (character === closing) {
      depth -= 1;
      if (depth === 0) return true;
    }
  }
  return false;
}

function addDiagnostic(frame, severity, message, kind = 'protocol') {
  frame.diagnostics.push({ severity, message, kind });
}

function validRequestId(id) {
  return id === null || typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
}

function validateJsonRpc(message) {
  const frame = {
    message,
    type: 'unknown',
    method: '',
    id: null,
    hasId: false,
    valid: false,
    diagnostics: [],
  };

  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    addDiagnostic(frame, 'error', 'A JSON-RPC message must be a JSON object.');
    frame.type = 'error';
    return frame;
  }

  const hasMethod = Object.hasOwn(message, 'method');
  const hasResult = Object.hasOwn(message, 'result');
  const hasError = Object.hasOwn(message, 'error');
  frame.hasId = Object.hasOwn(message, 'id');
  frame.id = frame.hasId ? message.id : null;
  frame.method = typeof message.method === 'string' ? message.method : '';

  if (message.jsonrpc !== '2.0') {
    addDiagnostic(frame, 'error', 'The jsonrpc field must be exactly "2.0".');
  }

  if (frame.hasId && !validRequestId(frame.id)) {
    addDiagnostic(frame, 'error', 'A request or response ID must be a string, number, or null.');
  }

  if (hasMethod) {
    frame.type = frame.hasId ? 'request' : 'notification';
    if (typeof message.method !== 'string' || message.method.trim() === '') {
      addDiagnostic(frame, 'error', 'A request or notification must contain a non-empty method string.');
    } else if (hasResult || hasError) {
      addDiagnostic(frame, 'error', 'A request or notification cannot also contain result or error.');
    } else if (!KNOWN_METHODS.has(message.method) && !message.method.startsWith('notifications/')) {
      addDiagnostic(frame, 'warning', `Unknown method "${message.method}". Check whether this method name is expected by your server.`);
    }
  } else {
    frame.type = hasError ? 'error' : 'response';
    if (!hasResult && !hasError) {
      addDiagnostic(frame, 'error', 'The message is missing a method or a response result/error field.');
    }
    if (!frame.hasId) {
      addDiagnostic(frame, 'error', 'A response must contain an id field.');
    }
    if (hasResult === hasError) {
      addDiagnostic(frame, 'error', 'A response must contain exactly one of result or error.');
    }
    if (hasError) {
      const rpcError = message.error;
      if (!rpcError || typeof rpcError !== 'object' || Array.isArray(rpcError)) {
        addDiagnostic(frame, 'error', 'The error field must be an object with a numeric code and string message.');
      } else {
        if (typeof rpcError.code !== 'number' || !Number.isFinite(rpcError.code)) {
          addDiagnostic(frame, 'error', 'The JSON-RPC error code must be a number.');
        }
        if (typeof rpcError.message !== 'string') {
          addDiagnostic(frame, 'error', 'The JSON-RPC error message must be a string.');
        }
        if (typeof rpcError.code === 'number' && typeof rpcError.message === 'string') {
          const knownName = ERROR_CODE_NAMES[String(rpcError.code)];
          const codeDescription = knownName ? ` (${knownName})` : '';
          addDiagnostic(frame, 'error', `Remote JSON-RPC error ${rpcError.code}${codeDescription}: ${rpcError.message}`, 'remote');
        }
      }
    }
  }

  frame.valid = frame.diagnostics.every(diagnostic => diagnostic.severity !== 'error' || diagnostic.kind === 'remote');
  return frame;
}

function normalizedLevel(text) {
  const source = String(text);
  const jsonStart = findJsonStart(source);
  const logPrefix = jsonStart < 0 ? source : source.slice(0, jsonStart);
  const match = logPrefix.match(/\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)\b/i);
  if (!match) return 'N/A';
  const level = match[1].toUpperCase();
  if (level === 'WARNING') return 'WARN';
  if (level === 'TRACE' || level === 'FATAL') return level === 'TRACE' ? 'DEBUG' : 'ERROR';
  return level;
}

function inferTransport(text) {
  if (/stdio\s+rx:/i.test(text)) return 'stdio rx';
  if (/stdio\s+tx:/i.test(text)) return 'stdio tx';
  if (/^\s*(?:event|data|id|retry):/im.test(text)) return 'SSE';
  if (findJsonStart(text) >= 0) return 'JSON';
  return 'text';
}

function frameFromText(text, options = {}) {
  const transport = options.transport || inferTransport(text);
  const payload = options.payload || parseJsonPayload(text);
  const frame = {
    number: 0,
    timestamp: parseTimestamp(text),
    timestampText: findTimestampText(text),
    level: normalizedLevel(text),
    transport,
    safeText: text,
    message: payload.value,
    type: 'unknown',
    method: '',
    id: null,
    hasId: false,
    valid: false,
    parseError: false,
    diagnostics: [],
  };

  if (payload.error) {
    frame.type = 'error';
    frame.parseError = true;
    addDiagnostic(frame, 'error', `Invalid JSON: ${payload.error.message}`);
    return [frame];
  }

  if (!payload.found) {
    if (/stdio\s+(?:rx|tx):/i.test(text) || /^\s*data:/im.test(text)) {
      frame.type = 'error';
      frame.parseError = true;
      addDiagnostic(frame, 'error', 'Expected a JSON message after the stdio or SSE prefix. The line is preserved below.');
    }
    return [frame];
  }

  const values = Array.isArray(payload.value) ? payload.value : [payload.value];
  return values.map(value => {
    const validated = validateJsonRpc(value);
    const result = { ...frame, ...validated, message: value, diagnostics: [...validated.diagnostics] };
    if (value && typeof value === 'object' && !Array.isArray(value) && !('jsonrpc' in value) && !('method' in value) && !('id' in value) && !('result' in value) && !('error' in value)) {
      result.type = 'unknown';
      result.diagnostics = [];
      addDiagnostic(result, 'warning', 'This is valid JSON, but it does not look like a JSON-RPC message.');
    }
    return result;
  });
}

function startsNewLogRecord(line) {
  return /^\s*(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\[?(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\]?\b|stdio\s+(?:rx|tx):|event:|data:)/i.test(line);
}

function parseSanitizedLog(sanitizedText) {
  const lines = String(sanitizedText).split(/\r?\n/);
  const frames = [];
  let sseMetadata = [];
  let sseData = [];

  function appendFrames(text, transport) {
    const newFrames = frameFromText(text, { transport });
    for (const frame of newFrames) {
      frame.number = frames.length + 1;
      frames.push(frame);
    }
  }

  function flushSse() {
    if (!sseData.length) return;
    const eventText = [...sseMetadata, ...sseData].join('\n');
    appendFrames(eventText, 'SSE');
    sseMetadata = [];
    sseData = [];
  }

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) {
      flushSse();
      sseMetadata = [];
      continue;
    }

    if (/^\s*(?:event|id|retry):/i.test(line) || /^\s*:/i.test(line)) {
      flushSse();
      sseMetadata.push(line);
      continue;
    }

    if (/^\s*data:/i.test(line)) {
      sseData.push(line);
      continue;
    }

    flushSse();
    sseMetadata = [];

    let record = line;
    let endIndex = index;
    const initialPayload = parseJsonPayload(record);
    if (initialPayload.found && initialPayload.error && !hasBalancedJson(record)) {
      while (endIndex + 1 < lines.length && !hasBalancedJson(record)) {
        const nextLine = lines[endIndex + 1];
        if (startsNewLogRecord(nextLine)) break;
        endIndex += 1;
        record += `\n${nextLine}`;
      }
    }
    appendFrames(record, inferTransport(record));
    index = endIndex;
  }

  flushSse();
  return frames;
}

function requestIdKey(id) {
  return `${typeof id}:${String(id)}`;
}

function calculateLatencyPairs(frames) {
  const pending = new Map();
  const pairs = [];

  for (const frame of frames) {
    if (!frame.valid || !frame.hasId) continue;

    if (frame.type === 'request') {
      const key = requestIdKey(frame.id);
      const existing = pending.get(key) || [];
      if (existing.length) {
        const warning = `Duplicate active request ID ${String(frame.id)}; matching uses the first outstanding request.`;
        addDiagnostic(frame, 'warning', warning);
        for (const previous of existing) {
          if (!previous.diagnostics.some(item => item.message === warning)) addDiagnostic(previous, 'warning', warning);
        }
      }
      existing.push(frame);
      pending.set(key, existing);
      continue;
    }

    if (frame.type !== 'response' && frame.type !== 'error') continue;
    const key = requestIdKey(frame.id);
    const existing = pending.get(key) || [];
    if (!existing.length) {
      addDiagnostic(frame, 'warning', `Response ID ${String(frame.id)} has no matching request.`);
      pairs.push({ request: null, response: frame, ms: null });
      continue;
    }

    if (existing.length > 1) {
      addDiagnostic(frame, 'warning', `Response ID ${String(frame.id)} is ambiguous because multiple requests are outstanding; the oldest request was matched.`);
    }
    const request = existing.shift();
    if (!existing.length) pending.delete(key);

    let ms = null;
    if (request.timestamp !== null && frame.timestamp !== null) {
      const difference = frame.timestamp - request.timestamp;
      if (difference >= 0) ms = difference;
      else addDiagnostic(frame, 'warning', 'Response timestamp is earlier than its request; latency is unavailable.');
    }
    pairs.push({ request, response: frame, ms });
  }

  for (const outstanding of pending.values()) {
    for (const request of outstanding) {
      addDiagnostic(request, 'warning', `Request ID ${String(request.id)} has no matching response.`);
      pairs.push({ request, response: null, ms: null });
    }
  }

  return pairs;
}

function analyzeLog(text) {
  const redaction = redactSecrets(text);
  const frames = parseSanitizedLog(redaction.text);
  const pairs = calculateLatencyPairs(frames);
  const toolLatencies = pairs
    .filter(pair => pair.request?.method === 'tools/call' && pair.response?.type === 'response' && pair.ms !== null)
    .map(pair => pair.ms);
  const diagnostics = frames.flatMap(frame => frame.diagnostics);
  return {
    frames,
    pairs,
    sanitizedText: redaction.text,
    redactedSecrets: redaction.count,
    validMessages: frames.filter(frame => frame.valid).length,
    protocolErrors: diagnostics.filter(item => item.severity === 'error').length,
    warnings: diagnostics.filter(item => item.severity === 'warning').length,
    averageToolLatency: toolLatencies.length
      ? toolLatencies.reduce((sum, value) => sum + value, 0) / toolLatencies.length
      : null,
  };
}

// Expose pure helpers only for local inspection and lightweight testing.
if (typeof globalThis !== 'undefined') {
  globalThis.MCPLogAnalyzerCore = Object.freeze({ redactSecrets, parseSanitizedLog, validateJsonRpc, calculateLatencyPairs, analyzeLog });
}

function createElement(tagName, className, text) {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = String(text);
  return element;
}

function renderDiagnostics(container, diagnostics) {
  if (!diagnostics.length) return;
  const list = createElement('ul', 'diagnostic-list');
  for (const diagnostic of diagnostics) {
    const item = createElement('li', `diagnostic-${diagnostic.severity}`, diagnostic.message);
    list.append(item);
  }
  container.append(list);
}

function renderFrame(frame) {
  const card = createElement('details', 'frame-card');
  const summary = createElement('summary', 'frame-summary');
  const shownType = frame.type === 'unknown' ? 'unknown' : frame.type;
  const cells = [
    createElement('span', 'frame-number', `#${frame.number}`),
    createElement('span', 'frame-time', frame.timestampText || 'No timestamp'),
    createElement('span', `badge badge-${shownType}`, shownType),
    createElement('span', 'frame-method', frame.method || (frame.parseError ? 'Malformed message' : '—')),
    createElement('span', 'frame-id', frame.hasId ? `ID ${String(frame.id)}` : '—'),
    createElement('span', 'frame-chevron', '⌄'),
  ];
  for (const cell of cells) summary.append(cell);

  const body = createElement('div', 'details-body');
  const metadata = createElement('div', 'frame-meta');
  metadata.append(
    createElement('span', '', `LEVEL ${frame.level}`),
    createElement('span', '', `TRANSPORT ${frame.transport}`),
    createElement('span', '', frame.valid ? 'VALID JSON-RPC 2.0' : frame.message ? 'JSON / NON-STANDARD RPC' : frame.parseError ? 'PARSE ISSUE' : 'PLAIN LOG'),
  );
  body.append(metadata);
  renderDiagnostics(body, frame.diagnostics);

  const details = frame.message === null ? frame.safeText : JSON.stringify(frame.message, null, 2);
  body.append(createElement('pre', 'frame-details', details));
  card.append(summary, body);
  return card;
}

function renderFrames() {
  const levelFilter = document.querySelector('#level-filter').value;
  const typeFilter = document.querySelector('#type-filter').value;
  const methodSearch = document.querySelector('#method-filter').value.trim().toLowerCase();
  const visible = currentAnalysis.frames.filter(frame =>
    (levelFilter === 'All' || frame.level === levelFilter)
    && (typeFilter === 'All' || frame.type === typeFilter)
    && (!methodSearch || frame.method.toLowerCase().includes(methodSearch)),
  );

  document.querySelector('#frame-count').textContent = `${visible.length} / ${currentAnalysis.frames.length}`;
  const list = document.querySelector('#frames-list');
  list.replaceChildren();
  if (!visible.length) {
    list.append(createElement('div', 'empty-state', 'No frames match these filters.'));
    return;
  }
  for (const frame of visible) list.append(renderFrame(frame));
}

function renderWaterfall() {
  const target = document.querySelector('#waterfall');
  target.replaceChildren();
  if (!currentAnalysis.pairs.length) {
    target.append(createElement('div', 'empty-state', 'No request and response cycles found. JSON-RPC IDs are used to match messages.'));
    return;
  }

  const measured = currentAnalysis.pairs.filter(pair => pair.ms !== null).map(pair => pair.ms);
  const maximum = Math.max(...measured, 1);
  for (const pair of currentAnalysis.pairs) {
    const row = createElement('div', 'waterfall-row');
    const request = pair.request;
    const response = pair.response;
    const label = request
      ? `${request.method || 'Unknown method'} · ID ${String(request.id)}`
      : `Unmatched response · ID ${String(response.id)}`;
    const labelCell = createElement('div', 'waterfall-label', request ? request.method || 'Unknown method' : 'Unmatched response');
    labelCell.title = label;
    labelCell.append(createElement('small', '', `ID ${String((request || response).id)}`));

    const timeline = createElement('div', 'timeline');
    if (pair.ms !== null) {
      const bar = createElement('div', 'timeline-bar');
      bar.style.width = `${Math.max(2, pair.ms / maximum * 100)}%`;
      timeline.append(bar);
    }
    const value = pair.ms === null
      ? createElement('div', 'latency-value unmatched', request && response ? 'Unavailable' : request ? 'No response' : 'No request')
      : createElement('div', 'latency-value', `${pair.ms.toFixed(1)} ms`);
    row.append(labelCell, timeline, value);
    target.append(row);
  }
}

let currentAnalysis = { frames: [], pairs: [], sanitizedText: '', redactedSecrets: 0, validMessages: 0, protocolErrors: 0, warnings: 0, averageToolLatency: null };

function clearAnalysisView() {
  currentAnalysis = { frames: [], pairs: [], sanitizedText: '', redactedSecrets: 0, validMessages: 0, protocolErrors: 0, warnings: 0, averageToolLatency: null };
  document.querySelector('#results').hidden = true;
  document.querySelector('#stat-frames').textContent = '0';
  document.querySelector('#stat-valid').textContent = '0';
  document.querySelector('#stat-latency').textContent = 'N/A';
  document.querySelector('#stat-secrets').textContent = '0';
  document.querySelector('#issue-summary').replaceChildren();
  document.querySelector('#frame-count').textContent = '0';
  document.querySelector('#waterfall').replaceChildren();
  document.querySelector('#frames-list').replaceChildren();
  document.querySelector('#sanitized-output').textContent = '';
  document.querySelector('#copy-status').textContent = '';
}

function renderAnalysis(analysis) {
  currentAnalysis = analysis;
  document.querySelector('#results').hidden = false;
  document.querySelector('#stat-frames').textContent = String(analysis.frames.length);
  document.querySelector('#stat-valid').textContent = String(analysis.validMessages);
  document.querySelector('#stat-latency').textContent = analysis.averageToolLatency === null
    ? 'N/A'
    : `${analysis.averageToolLatency.toFixed(1)} ms`;
  document.querySelector('#stat-secrets').textContent = String(analysis.redactedSecrets);
  document.querySelector('#sanitized-output').textContent = analysis.sanitizedText;

  const issueSummary = document.querySelector('#issue-summary');
  issueSummary.replaceChildren();
  issueSummary.append(
    createElement('span', 'bad', `${analysis.protocolErrors} protocol error${analysis.protocolErrors === 1 ? '' : 's'}`),
    createElement('span', '', ' · '),
    createElement('span', 'warn', `${analysis.warnings} warning${analysis.warnings === 1 ? '' : 's'}`),
  );
  renderWaterfall();
  renderFrames();
}

function initializeApp() {
  const input = document.querySelector('#log-input');
  const fileInput = document.querySelector('#file-input');
  const inputStatus = document.querySelector('#input-status');

  input.addEventListener('input', () => {
    if (!document.querySelector('#results').hidden) clearAnalysisView();
  });

  // Embedded sample text means the buttons also work when index.html is opened as file://.
  const samples = {
    'filesystem-trace.log': `2025-02-14T10:22:01.000Z INFO MCP filesystem server starting
2025-02-14T10:22:01.120Z INFO stdio rx: {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo-client","version":"1.0"}}}
2025-02-14T10:22:01.245Z INFO stdio tx: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"filesystem","version":"2.1"}}}
2025-02-14T10:22:01.300Z DEBUG stdio rx: {"jsonrpc":"2.0","method":"notifications/initialized"}
2025-02-14T10:22:02.010Z INFO stdio rx: {"jsonrpc":"2.0","id":2,"method":"tools/list"}
2025-02-14T10:22:02.085Z INFO stdio tx: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file"},{"name":"list_directory"}]}}
2025-02-14T10:22:03.000Z INFO stdio rx: {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/docs/guide.md"}}}
2025-02-14T10:22:03.184Z INFO stdio tx: {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Sample file content"}]}}`,
    'protocol-errors.log': `2025-03-08T16:40:00.000Z INFO stdio rx: {"jsonrpc":"2.0","id":10,"method":"initialize"}
2025-03-08T16:40:00.080Z INFO stdio tx: {"jsonrpc":"2.0","id":10,"result":{"protocolVersion":"2025-03-26"}}
2025-03-08T16:40:01.000Z WARN stdio rx: {"jsonrpc":"2.0","method":"notifications/initialized"}
2025-03-08T16:40:02.000Z INFO stdio rx: {"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"get_status"}}
2025-03-08T16:40:02.045Z ERROR stdio tx: {"jsonrpc":"2.0","id":11,"error":{"code":-32601,"message":"Method not found"}}
2025-03-08T16:40:03.000Z INFO stdio rx: {"jsonrpc":"1.0","id":12,"method":"tools/call","params":{"api_key":"sk-fakeSampleKey0123456789"}}
2025-03-08T16:40:03.020Z INFO stdio rx: {"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"github_token":"ghp_0123456789abcdefghijklmnopqrstuv"}}
2025-03-08T16:40:03.040Z INFO stdio rx: {"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"authorization":"Bearer fakeBearerToken_12345678901234567890"}}
2025-03-08T16:40:03.060Z INFO stdio rx: {"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"database":"postgresql://demo:fakePassword@localhost:5432/sampledb"}}
2025-03-08T16:40:04.000Z ERROR stdio rx: {"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"bad-json"}
2025-03-08T16:40:05.000Z ERROR stdio rx: {"jsonrpc":"2.0","id":17,"method":"tools/call","params":`,
    'sse-multitool.log': `event: message 2025-05-12T12:00:00.000Z INFO
id: 1
data: {"jsonrpc":"2.0","id":"tool-1","method":"tools/call","params":{"name":"search_files","arguments":{"query":"*.md"}}}

event: message 2025-05-12T12:00:00.120Z INFO
id: 2
data: {"jsonrpc":"2.0","id":"tool-1","result":{"content":[{"type":"text","text":"2 files found"}]}}

event: message 2025-05-12T12:00:00.200Z INFO
data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}

event: message 2025-05-12T12:00:01.000Z INFO
id: 3
data: {"jsonrpc":"2.0","id":"tool-2","method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}

event: message 2025-05-12T12:00:01.275Z INFO
id: 4
data: {"jsonrpc":"2.0","id":"tool-2","result":{"content":[{"type":"text","text":"Sample README"}]}}

event: message 2025-05-12T12:00:02.000Z INFO
id: 5
data: {"jsonrpc":"2.0","id":"tool-3","method":"resources/read","params":{"uri":"file:///workspace/README.md"}}

event: message 2025-05-12T12:00:02.090Z INFO
id: 6
data: {"jsonrpc":"2.0","id":"tool-3","result":{"contents":[{"uri":"file:///workspace/README.md","text":"Sample read"}]}}`,
  };

  document.querySelector('#analyze-button').addEventListener('click', () => {
    if (!input.value.trim()) {
      inputStatus.textContent = 'Paste or load a log before analyzing.';
      return;
    }
    const analysis = analyzeLog(input.value);
    renderAnalysis(analysis);
    inputStatus.textContent = `${analysis.frames.length} frames analyzed locally`;
    document.querySelector('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  document.querySelector('#clear-button').addEventListener('click', () => {
    input.value = '';
    clearAnalysisView();
    document.querySelector('#level-filter').value = 'All';
    document.querySelector('#type-filter').value = 'All';
    document.querySelector('#method-filter').value = '';
    document.querySelector('#copy-status').textContent = '';
    inputStatus.textContent = 'Input and results cleared from this page.';
  });

  document.querySelector('#upload-button').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    if (!file) return;
    if (!/\.(?:log|txt|json)$/i.test(file.name)) {
      inputStatus.textContent = 'Choose a .log, .txt, or .json file.';
      fileInput.value = '';
      return;
    }
    try {
      input.value = await file.text();
      clearAnalysisView();
      inputStatus.textContent = `Loaded ${file.name} · ${file.size.toLocaleString()} bytes locally`;
    } catch {
      inputStatus.textContent = 'The selected file could not be read.';
    }
    fileInput.value = '';
  });

  document.querySelectorAll('[data-sample]').forEach(button => {
    button.addEventListener('click', () => {
      clearAnalysisView();
      input.value = samples[button.dataset.sample] || '';
      inputStatus.textContent = `Loaded sample: ${button.textContent.trim()}`;
    });
  });

  for (const selector of ['#level-filter', '#type-filter', '#method-filter']) {
    document.querySelector(selector).addEventListener('input', renderFrames);
  }
  document.querySelector('#reset-filters').addEventListener('click', () => {
    document.querySelector('#level-filter').value = 'All';
    document.querySelector('#type-filter').value = 'All';
    document.querySelector('#method-filter').value = '';
    renderFrames();
  });

  document.querySelector('#copy-button').addEventListener('click', async () => {
    const status = document.querySelector('#copy-status');
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(currentAnalysis.sanitizedText);
      } else {
        const helper = document.createElement('textarea');
        helper.value = currentAnalysis.sanitizedText;
        helper.style.position = 'fixed';
        helper.style.opacity = '0';
        document.body.append(helper);
        helper.select();
        const copied = document.execCommand('copy');
        helper.remove();
        if (!copied) throw new Error('Clipboard access is unavailable.');
      }
      status.textContent = 'Sanitized logs copied to clipboard.';
    } catch {
      status.textContent = 'Clipboard access is unavailable. Select and copy the sanitized stream above.';
    }
  });

  document.querySelector('#download-button').addEventListener('click', () => {
    const blob = new Blob([currentAnalysis.sanitizedText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'sanitized-mcp-logs.log';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}

if (typeof document !== 'undefined') initializeApp();
