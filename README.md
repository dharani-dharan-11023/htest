# htest

## Security Analysis: HTTP Calls and C2 Behavior

This repository contains a decompiled copy of the **HARPA AI** Chrome browser extension (v9.8.0). The analysis below documents all outbound HTTP/WebSocket calls and Command-and-Control (C2)-like behaviors identified in the codebase.

---

## HTTP Calls

The extension makes outbound HTTP requests to the following endpoints across its JavaScript files (`bg.js`, `os.js`, `cs.js`, `pp.js`):

| Endpoint | Purpose | File |
|---|---|---|
| `https://api.harpa.ai/api/v1` | Main backend API (auth, chats, recipes, commands) | `bg.js`, `os.js`, `pp.js` |
| `https://api.mixpanel.com/track?ip=1` | Analytics/telemetry tracking with IP-based geolocation | `bg.js`, `pp.js` |
| `https://whatismyipaddress.com/` | Scrapes user's public IP address and geographic location | `bg.js` |
| `https://api.openai.com` | OpenAI API calls (GPT models) | `bg.js`, `pp.js` |
| `https://claude.ai/api/organizations` | Anthropic Claude API calls | `bg.js` |
| `https://gemini.google.com` | Google Gemini API calls | `bg.js` |
| `https://openrouter.ai/api` | OpenRouter AI routing | `bg.js`, `pp.js` |
| `https://chatgpt.com/backend-api/conversation` | ChatGPT session API (with credentials) | `bg.js` |
| `https://harpa.ai` / `https://app.harpa.ai` | Extension web app and welcome pages | `bg.js`, `cs.js` |
| `https://gun.harpa.ai:3000` | GunDB real-time relay server (WebSocket) | `bg.js`, `os.js` |

**Total `fetch()` calls counted:**
- `bg.js`: ~46 calls
- `os.js`: ~4 calls
- `cs.js`: ~2 calls

---

## C2 (Command and Control) Behavior

The following behaviors in the codebase exhibit characteristics commonly associated with C2 infrastructure:

### 1. Persistent WebSocket Connection to `gun.harpa.ai:3000`

**File:** `os.js`, `bg.js`

The extension establishes a persistent WebSocket connection to `wss://gun.harpa.ai:3000/ws` using the `createWebSocket()` method. This connection:

- Reconnects automatically with exponential back-off (up to 15 minutes) on close/error
- Receives JSON messages from the server in real-time
- Dispatches received messages internally via `r.send("grid.ws.message", t)`

This is a classic C2 channel: the server can push arbitrary JSON commands to the extension at any time without the user initiating a request.

```js
// os.js — WebSocket connection to gun.harpa.ai
this.ws = new WebSocket(`${s.gunUrl}/ws?${channelsParams}`);
this.ws.onmessage = e => {
  let t = e.data;
  if (t?.startsWith("{") && t?.endsWith("}")) t = JSON.parse(t);
  r.send("grid.ws.message", t); // dispatches to internal message bus
};
this.ws.onclose = () => { this.reconnect(e, t); }; // auto-reconnects
```

### 2. User IP Address and Location Collection

**File:** `bg.js`

The extension fetches `https://whatismyipaddress.com/` and scrapes the user's public IP address, ISP, and geographic location from the HTML response. This data is stored in `billing.location` and `billing.locationCollectedOn` in extension local storage and is sent to the HARPA backend.

```js
// bg.js — IP and location scraping
const e = await fetch("https://whatismyipaddress.com/");
const t = await e.text();
// parses <p class="information"> to extract location
```

### 3. Mixpanel Telemetry with IP Tracking

**File:** `bg.js`, `pp.js`

The extension sends analytics events to `https://api.mixpanel.com/track?ip=1`. The `ip=1` parameter instructs Mixpanel to resolve and record the user's IP address server-side. Events include the `distinct_id` (tied to the user's `agentId`), extension version, environment, and user locus (the execution context — e.g., background service worker `bg`, content script `cs`, offscreen document `os`, or page panel `pp`).

### 4. Hidden Offscreen iframe Loading `harpa.ai/oi`

**File:** `os.js`

The extension creates a hidden `<iframe>` in an offscreen document pointing to `https://harpa.ai/oi`. This iframe is used as a real-time communication bridge between the extension and the HARPA web service, enabling the server to interact with the extension without visible user action.

```js
// os.js — Hidden iframe bridge
this._iframe = document.createElement("iframe");
this._iframe.src = `${s.webUrl}/oi`; // https://harpa.ai/oi
document.body.append(this._iframe);
```

### 5. Remote Recipe and Command Fetching

**File:** `bg.js`

The extension fetches automation recipes and commands from `https://api.harpa.ai/api/v1/recipes/install` and `https://api.harpa.ai/api/v1/commands`. These can contain executable automation workflows that the extension runs locally on the user's browser.

---

## Summary

| Behavior | C2 Indicator | Severity |
|---|---|---|
| Persistent WebSocket to `gun.harpa.ai:3000` | Real-time server-push channel | High |
| IP address scraping from `whatismyipaddress.com` | Data exfiltration / user tracking | Medium |
| Mixpanel tracking with `ip=1` | User tracking with IP resolution | Medium |
| Hidden iframe bridge to `harpa.ai/oi` | Covert server communication channel | Medium |
| Remote recipe/command execution | Remote code execution via commands | High |

> **Note:** While these behaviors are consistent with C2 techniques, they may be intentional product features of the HARPA AI extension (telemetry, sync, remote automation). The presence of these patterns does not necessarily indicate malicious intent, but they represent significant privacy and security concerns for end users.
