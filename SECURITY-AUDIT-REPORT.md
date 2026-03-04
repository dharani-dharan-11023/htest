# HARPA AI Browser Extension (v9.8.0) - Security Audit Report

**Date:** 2026-03-04
**Extension:** HARPA AI | Browser's Mind
**Version:** 9.8.0
**Manifest:** V3
**Auditor:** Automated Static Analysis
**Classification:** L9 Security Surface - Critical Attack Surface Analysis

---

## Executive Summary

This audit identifies **multiple critical-severity vulnerabilities** in the HARPA AI browser extension that, when chained together, present a devastating attack surface. The extension runs content scripts on **every website** (`*://*/*`), requests **wildcard host permissions**, and employs unsafe code execution primitives throughout its architecture. A malicious website can exploit these flaws to achieve **full extension compromise**, **cross-origin data theft**, **session hijacking**, and **arbitrary code execution** in the extension's privileged context.

**Overall Risk Rating: CRITICAL**

---

## 1. Architecture Overview

### 1.1 Extension Components

| Component | File(s) | Context | Runs On |
|-----------|---------|---------|---------|
| Service Worker (Background) | `bg.js` (1.4 MB) | Privileged | Always |
| Content Script (Universal) | `cs.js` (38 KB) | Content | `*://*/*` (ALL sites) |
| Content Script (OpenAI) | `cs-openai.js` (5 KB) | Content | `*.openai.com` |
| Content Script (Web) | `cs-web.js` (5 KB) | Content | `harpa.ai`, `localhost:3000` |
| Injected Page Script | `nj.js` (11 KB) | Page | Injected into pages |
| Injected Engine | `nj-engine.js` (129 KB) | Page | Injected into pages |
| Popup/Panel UI | `pp.js` (1.7 MB) | Extension | Extension pages |
| Offscreen Document | `os.js` (33 KB) | Extension | Offscreen |
| Offscreen Iframe Target | `oi.js` (24 KB) | Web | `harpa.ai/oi` |

### 1.2 Permissions (manifest.json)

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

**Assessment:** The extension requests the **maximum possible permission set**. `browsingData` allows wiping browsing history. `cookies` with `*://*/*` host permissions allows reading/writing cookies for ANY domain. `scripting` allows injecting arbitrary code into any page. `declarativeNetRequest` can modify HTTP requests/responses. This creates an enormous blast radius if any component is compromised.

---

## 2. Critical Vulnerabilities

### CVE-CLASS-001: Arbitrary Code Execution via `onreset` Handler Trick

**Severity:** CRITICAL (CVSS 9.8)
**Files:** `cs.js:1` (executeJs method), `cs-openai.js:1`, `bg.js`
**CWE:** CWE-94 (Improper Control of Generation of Code)

#### Description

The extension uses a novel technique to execute arbitrary JavaScript in the page context by abusing DOM event handler attributes:

```javascript
// cs.js - $startup.controller.executeJs()
executeJs(t,...e) {
  s.is.function(t) && (t = `(${t.toString()}).call(null, ...${JSON.stringify(e)})`);
  const i = document.createElement("div");
  i.setAttribute("onreset", `const URL = window.URL; ${t}`);
  i.dispatchEvent(new Event("reset"));
}
```

This method:
1. Creates a `<div>` element
2. Sets its `onreset` attribute to arbitrary JavaScript code
3. Dispatches a `reset` event to trigger execution

**Attack Vector:** Any code path that reaches `executeJs()` with attacker-controlled input achieves arbitrary page-context code execution. Since the content script runs on ALL sites, a compromised message channel immediately grants universal code execution.

---

### CVE-CLASS-002: Trusted Types Policy Override - CSP Bypass

**Severity:** CRITICAL (CVSS 9.6)
**File:** `cs.js:1` (_patchTrustedTypes method)
**CWE:** CWE-693 (Protection Mechanism Failure)

#### Description

The extension **overrides the browser's Trusted Types security policy** to allow any string as trusted:

```javascript
_patchTrustedTypes() {
  this.executeJs(() => {
    const t = trustedTypes.createPolicy.bind(trustedTypes);
    trustedTypes.createPolicy = (e, i) => t(e, "default" !== e ? i : {
      createHTML: t => t,       // ANY string is "trusted" HTML
      createScript: t => t,     // ANY string is "trusted" script
      createScriptURL: t => t   // ANY URL is "trusted" script source
    });
  });
}
```

**Impact:** This **completely disables Trusted Types** protections on every website the extension runs on. Trusted Types is a critical XSS defense mechanism. By replacing the `default` policy with a pass-through, the extension makes every website vulnerable to DOM XSS attacks that Trusted Types would otherwise prevent.

---

### CVE-CLASS-003: Service Worker Registration Interception

**Severity:** HIGH (CVSS 8.6)
**File:** `cs.js:1` (_patchServiceWorker method)
**CWE:** CWE-693 (Protection Mechanism Failure)

#### Description

The extension intercepts and conditionally blocks Service Worker registrations:

```javascript
_patchServiceWorker() {
  this.executeJs(() => {
    const t = navigator.serviceWorker.register;
    navigator.serviceWorker.register = async function(...e) {
      try {
        if ((await fetch(e[0]).then(t => t.text()))
            .toLowerCase().includes("content-security-policy"))
          return;  // SILENTLY BLOCKS registration
      } catch (t) { console.error(t); }
      return t.call(this, ...e);
    };
  });
}
```

**Impact:** The extension fetches Service Worker scripts and blocks registration if they contain CSP headers. This:
1. Silently breaks website security mechanisms
2. Fetches script content cross-origin (information leak)
3. Gives attackers a TOCTOU race condition to bypass the check

---

### CVE-CLASS-004: Universal postMessage Without Origin Validation

**Severity:** CRITICAL (CVSS 9.1)
**Files:** `cs.js`, `nj.js`, `nj-engine.js`, `oi.js`, `os.js`
**CWE:** CWE-346 (Origin Validation Error)

#### Description

The extension's internal bus system (`$bus`) uses `window.postMessage()` extensively with **wildcard origin `"*"` and no origin validation on received messages**.

**Sending with wildcard origin:**
```javascript
// cs.js - _propagateEvents
window.addEventListener("message", async ({data: s}) => {
  // NO origin check
  if (s.frameName === t.frameName && "execute" === s.type) {
    await n.send("engine.executeJs", this._tabId, s.js);  // EXECUTES JS!
    return;
  }
  await chrome.runtime.sendMessage(s);  // FORWARDS TO BACKGROUND
});
```

```javascript
// Multiple locations
window.postMessage(n, "*");   // Wildcard origin
parent.postMessage(r, "*");   // Wildcard origin
```

**Receiving without validation:**
```javascript
// nj.js - _setupNj
e = async ({data: e}) => {
  if (!this._isBusMsg(e)) return;     // Only checks appName
  if ("cs" !== e.locus) return;        // Attacker can set locus:"cs"
  const t = await this._callHandlers(e);
  r.postMessage({resId: e.reqId, result: t}, "*");
};
r.addEventListener("message", e);
```

**The `_isBusMsg` check is trivially bypassable:**
```javascript
_isBusMsg: e => e && e.$bus && e.appName === "__app_hrp"
```

Any webpage can send:
```javascript
window.postMessage({
  $bus: true,
  appName: "__app_hrp",
  locus: "cs",
  name: "engine.executeJs",
  args: [tabId, "alert('pwned')"]
}, "*");
```

**Impact:** Any malicious website can:
1. Send commands to the content script
2. Trigger `engine.executeJs` to run arbitrary JavaScript
3. Forward messages to the background service worker
4. Exfiltrate data from postMessage responses (sent with `"*"`)

---

### CVE-CLASS-005: Iframe Engine Injection - Arbitrary JS Execution Chain

**Severity:** CRITICAL (CVSS 9.8)
**File:** `cs.js:1` (engine controller + injector)
**CWE:** CWE-94 (Code Injection)

#### Description

The engine controller accepts configuration via multiple untrusted channels:

```javascript
// cs.js - engine.controller.init()
const s = window.frameElement?.getAttribute("__hrp")
  || window.location.href?.match(/[?&#]__hrp=(?<name>([a-zA-Z\d\-._]*:?){6})/)?.groups?.name
  || window.name;

let r = null;
try { r = JSON.parse(atob(s)); } catch {}
```

**Attack chain:**
1. Configuration is parsed from `window.name` (attacker-controlled via `window.open`)
2. Or from URL parameter `__hrp` (attacker-controlled)
3. Or from `frameElement` attribute (attacker-controlled in iframes)
4. Configuration is base64-decoded and JSON-parsed
5. The resulting config controls **what patches are applied**, including arbitrary navigator spoofing

```javascript
_constructNavigator(t) {
  if (t.navigator)
    for (const e in t.navigator) {
      const i = { get: () => t.navigator[e] };
      Object.defineProperty(navigator, e, i);
    }
}
```

**Impact:** An attacker who opens a window with a crafted `window.name` (base64-encoded JSON) can:
1. Control what "patches" are injected (disabling prompts, notifications, visibility)
2. Spoof the navigator object
3. Inject configuration that propagates through the extension's messaging

---

### CVE-CLASS-006: Web-Accessible Resources Exposed to All Origins

**Severity:** HIGH (CVSS 7.5)
**File:** `manifest.json:76-94`
**CWE:** CWE-200 (Exposure of Sensitive Information)

#### Description

```json
"web_accessible_resources": [{
  "resources": [
    "oi.js", "nj.js", "nj.css", "nj-engine.js", "nj-engine.css",
    "nj-youtube.js", "js/timer-worker.js", "js/pdf.min.js",
    "js/pdf.worker.min.js", "img/misc/shortcut.svg",
    "img/commands/*.svg", "harpa.html"
  ],
  "matches": ["*://*/*"]
}]
```

**Impact:**
1. **Extension fingerprinting:** Any website can detect HARPA is installed by probing `chrome-extension://<id>/oi.js`
2. **Source code analysis:** All injected scripts are readable by any website, allowing attackers to study the bus protocol and craft targeted attacks
3. **UI page access:** `harpa.html` (the full extension UI) is accessible from any origin

---

### CVE-CLASS-007: Arkose/CAPTCHA Bypass Infrastructure

**Severity:** HIGH (CVSS 7.8)
**Files:** `cs-openai.js`, `oi.js`
**CWE:** CWE-290 (Authentication Bypass by Spoofing)

#### Description

The extension contains infrastructure to bypass Arkose Labs CAPTCHA on OpenAI:

```javascript
// cs-openai.js - arkoseController
_patchFetch() {
  // Intercepts fetch() to rewrite CAPTCHA parameters
  globalThis.fetch = function (...args) {
    opts.body = opts.body.replace(
      /&${n}=[^&]+/,
      '&${n}=${encodeURIComponent(e)}'
    );
    return fetch0.call(this, ...args);
  }
}

_patchHeadAppendChild() {
  // Intercepts script loading to rewrite CAPTCHA script URLs
  HTMLElement.prototype.appendChild = function (...args) {
    url.searchParams.set('${n}', '${e}');
    elem.src = url.href;
  }
}

_patchEnforcement() {
  // Patches Object.prototype to intercept CAPTCHA enforcement config
  Object.defineProperty(Object.prototype, enf.$sent, { ... });
  Object.defineProperty(Object.prototype, enf.$isSDK, { ... });
}
```

**Impact:**
1. The extension modifies `Object.prototype` globally - this affects ALL JavaScript on the page
2. `HTMLElement.prototype.appendChild` is globally patched - breaking any website's script loading
3. These patches persist and affect all code running in the page context
4. Prototype pollution via `Object.defineProperty(Object.prototype, ...)` can be leveraged by attackers

---

### CVE-CLASS-008: Cross-Origin Data Exfiltration via Offscreen Document

**Severity:** HIGH (CVSS 8.1)
**Files:** `os.js`, `oi.js`
**CWE:** CWE-200 (Information Exposure)

#### Description

The offscreen document (`os.js`) creates an iframe to `https://harpa.ai/oi` and establishes a bidirectional communication channel:

```javascript
// os.js - iframeController
_createIframe() {
  const e = document.createElement("iframe");
  e.src = "https://harpa.ai/oi";
  e.name = `offscreen-iframe | ${chrome.runtime.getURL("/oi.js")}`;
  document.body.append(e);
  // Extension ID is leaked in the iframe name
}
```

The offscreen document bridges messages between the extension and the remote harpa.ai website:

```javascript
// cs-web.js - _propagateEvents
window.addEventListener("message", ({data: e}) => {
  this._isAllowed(e) && chrome.runtime.sendMessage(e);
});
chrome.runtime.onMessage.addListener(e => {
  this._isAllowed(e) && window.postMessage({...e, __processed: true}, "*");
});
```

**Impact:**
1. Extension ID is exposed to the remote website
2. The `harpa.ai` website can send messages that reach the privileged background context
3. If `harpa.ai` is compromised (supply chain), an attacker gains full extension control
4. The offscreen iframe has access to `localStorage` operations via bus messages

---

### CVE-CLASS-009: Navigator/Environment Spoofing Injection

**Severity:** MEDIUM (CVSS 6.5)
**File:** `cs.js:1` (injector._insertPatches)
**CWE:** CWE-74 (Injection)

#### Description

The extension injects patches that override critical browser APIs on every page:

```javascript
// Patches injected into every page:
"no-prompt"()     { window.prompt = () => {} },
"force-visible"() {
  document.visibilityState = "visible";  // Lies about tab visibility
  document.hidden = false;
  document.hasFocus = () => true;
},
"no-notification"() {
  Notification.permission = "denied";
  Notification.requestPermission = () => Promise.resolve("denied");
}
```

**Impact:** These patches:
1. Disable `window.prompt()` - breaks legitimate website security dialogs
2. Make the document always appear "visible" - defeats anti-automation checks
3. Block notification permissions - breaks site functionality
4. Can be abused by attackers to bypass visibility-based security checks

---

### CVE-CLASS-010: Sensitive DOM Content Harvesting

**Severity:** HIGH (CVSS 8.0)
**Files:** `nj-engine.js`, `os.js`
**CWE:** CWE-200 (Information Exposure)

#### Description

The extension implements full-page content extraction capabilities:

```javascript
// os.js - engine.htmlToText
htmlToText: async e => {
  // Strips scripts/styles, extracts ALL text content from pages
  // Including headings, paragraphs, form content
  // Removes security elements (nav, header, footer, iframe, etc.)
  // Returns sanitized text
}
```

```javascript
// os.js - YouTube transcript extraction
getTranscript: async e => {
  const t = await fetch(e, {credentials: "include"});
  // Extracts XSRF tokens from page
  // Makes authenticated POST requests
  // Extracts full video transcripts
}
```

```javascript
// os.js - PDF content extraction
_readPdf(e) {
  // Loads pdf.js library
  // Extracts full text from PDF files
}
```

**Impact:** Combined with the postMessage vulnerabilities, an attacker could:
1. Trigger page content extraction on any website
2. Access YouTube data with the user's credentials
3. Extract PDF content
4. Receive the results via the unsecured message channel

---

## 3. Attack Chain Summary

### Chain A: Remote Code Execution via postMessage (No User Interaction)

```
Attacker Website
  │
  ├─1─ window.postMessage({$bus:true, appName:"__app_hrp", name:"...", args:[...]}, "*")
  │    (No origin validation on receiver)
  │
  ├─2─ Message reaches cs.js content script event handler
  │    (Only checks appName === "__app_hrp")
  │
  ├─3─ Handler forwards to chrome.runtime.sendMessage()
  │    (Content script → Background service worker bridge)
  │
  ├─4─ Background executes handler (privileged context)
  │    Has access to: cookies, tabs, scripting, browsingData
  │
  └─5─ Response sent back via postMessage(result, "*")
       (Wildcard origin - attacker receives the result)
```

### Chain B: Extension Takeover via harpa.ai Compromise

```
Compromise harpa.ai (supply chain)
  │
  ├─1─ oi.js iframe receives messages from harpa.ai/oi
  │
  ├─2─ os.js offscreen document bridges to extension
  │
  ├─3─ Messages forwarded to bg.js service worker
  │
  └─4─ Full extension compromise:
       ├── Read/write ALL cookies (any domain)
       ├── Execute scripts in ANY tab
       ├── Modify network requests
       ├── Access browsing history
       └── Wipe browsing data
```

### Chain C: Trusted Types Disable + XSS Amplification

```
Any website with Trusted Types CSP
  │
  ├─1─ HARPA cs.js loads, patches trustedTypes.createPolicy
  │    Default policy now accepts ALL strings
  │
  ├─2─ Website's Trusted Types protection is DISABLED
  │
  ├─3─ DOM XSS that would be blocked now succeeds
  │
  └─4─ Attacker achieves XSS on "protected" websites
```

---

## 4. Permissions Blast Radius Assessment

| Permission | Abuse Potential After Compromise |
|------------|--------------------------------|
| `cookies` + `*://*/*` | Read/write cookies for ANY domain (session hijacking) |
| `scripting` | Inject and execute code in ANY tab |
| `browsingData` | Delete browsing history, cookies, cache (evidence destruction) |
| `tabs` | Enumerate all open tabs, read URLs (surveillance) |
| `declarativeNetRequest` | Modify HTTP headers, redirect requests (MITM) |
| `storage` | Persist malicious data, read user settings |
| `offscreen` | Maintain persistent background execution |
| `downloads` (optional) | Download files to user's system |

---

## 5. Recommendations

### Immediate (P0)

1. **Add origin validation to ALL postMessage handlers** - Check `event.origin` against an allowlist before processing any message
2. **Remove `executeJs` onreset trick** - Replace with proper `chrome.scripting.executeScript` from the service worker
3. **Remove Trusted Types override** - This actively harms user security on every website
4. **Remove Service Worker registration interception** - This breaks web security mechanisms
5. **Restrict `web_accessible_resources`** to specific origins, not `*://*/*`

### Short-term (P1)

6. **Reduce permissions** - `browsingData` and wildcard `host_permissions` are overprivileged
7. **Use `chrome.runtime.sendMessage` instead of `postMessage`** for CS↔NJ communication
8. **Validate all bus message names** against an allowlist of expected commands
9. **Remove Object.prototype modifications** in the Arkose controller
10. **Don't expose extension ID** in iframe names or DOM attributes

### Long-term (P2)

11. **Implement message signing** between extension components
12. **Adopt least-privilege architecture** - Split into multiple extensions with minimal permissions
13. **Remove code obfuscation** - Makes security review difficult, does not deter attackers
14. **Implement CSP for extension pages** stricter than `script-src 'self'`
15. **Regular third-party security audits**

---

## 6. Appendix: Files Analyzed

| File | Size | Findings |
|------|------|----------|
| `manifest.json` | 2.2 KB | Overprivileged permissions, wildcard WAR |
| `cs.js` | 38.6 KB | executeJs, Trusted Types bypass, SW interception, postMessage |
| `cs-openai.js` | 5 KB | Object.prototype pollution, fetch interception |
| `cs-web.js` | 5 KB | Unvalidated message bridge to extension |
| `nj.js` | 11.4 KB | postMessage without origin check |
| `nj-engine.js` | 129 KB | postMessage wildcard, new Function(), DOM injection |
| `oi.js` | 24 KB | postMessage to parent without origin check |
| `os.js` | 33 KB | Sensitive data handling, iframe to remote origin |
| `bg.js` | 1.4 MB | (minified - service worker, full privileged context) |
| `pp.js` | 1.7 MB | (minified - extension UI) |

---

*This report is intended for defensive security purposes and responsible disclosure.*
