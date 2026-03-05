# HARPA AI v9.8.0 — Zero-Interaction Supply Chain Attack Vectors

## Executive Summary

This analysis focuses exclusively on supply chain attack vectors that require **ZERO user intervention** — attacks that execute automatically just by having the extension installed. No clicking, no importing, no visiting specific pages. The extension's auto-executing background worker, auto-injected content scripts, and periodic alarm-based fetches create a fully passive attack surface.

---

## 1. Remote Configuration Auto-Fetch on Every Browser Startup (CRITICAL)

**Trigger:** Automatic — runs on every Chrome startup and every 3 hours via alarm

**File:** `bg.js` — Background service worker

```javascript
// Initialization chain (auto-runs on service worker start):
t.controller.init()
  → feature.controller.init()
    → this.updateOnInit()
      → this._update(true)

// Auto-fetches remote config:
async _update(e=false) {
  const i = e
    ? `${n.apiUrl}/feature?hash=${e}&v=${n.versionNumber}`
    : `${n.apiUrl}/feature?v=${n.versionNumber}`;
  const r = await fetch(i);  // ← AUTOMATIC fetch to api.harpa.ai
  // Response directly merged into extension state:
  Object.assign(o.feature, r);
}

// Recurring alarm — re-fetches every 3 hours:
chrome.alarms.run(this._update, {
  name: "feature.update",
  delayInMinutes: 180,    // 3 hours
  periodInMinutes: 180,   // every 3 hours
  immediately: true       // also runs immediately on init
});
```

**Attack chain:**
```
Compromise api.harpa.ai server OR MITM the connection
    → Inject malicious feature config in /feature response
    → Config is merged directly into extension state via Object.assign()
    → Feature flags control billing, analytics, task execution, AI routing
    → Altered flags can enable hidden functionality or redirect AI traffic
    → Affects ALL users within 3 hours (alarm cycle)
    → No user interaction needed — runs on every Chrome launch
```

**Why this is zero-interaction:** The `bg.js` service worker starts automatically when Chrome launches. The `controller.init()` chain calls `updateOnInit()` immediately, which fetches remote config from `api.harpa.ai`. The response is merged into the extension's state without schema validation. Additionally, a `chrome.alarms` timer re-fetches every 3 hours, ensuring persistent compromise even if Chrome stays open.

---

## 2. Content Script Auto-Injection on Every Page Load (CRITICAL)

**Trigger:** Automatic — injected on every webpage the user visits

**File:** `manifest.json`

```json
{
  "content_scripts": [
    {
      "matches": ["*://*/*"],           // ← ALL websites
      "exclude_matches": ["https://harpa.ai/oi", "http://localhost:3000/oi"],
      "js": ["/cs.js"],
      "run_at": "document_start",       // ← Before page even loads
      "all_frames": true                // ← Including all iframes
    }
  ]
}
```

**What cs.js does automatically on every page:**

```javascript
// 1. Sets up postMessage listener (no origin check):
window.addEventListener("message", (e) => {
  if (e.$bus === true && e.appName === "__app_hrp") {  // spoofable
    chrome.runtime.sendMessage(e);  // forwards to bg.js
  }
});

// 2. Injects nj.js into page context (web_accessible_resource):
//    Creates <script> tag pointing to chrome-extension://ID/nj.js

// 3. Disables Trusted Types on the page:
_patchTrustedTypes() {
  trustedTypes.createPolicy = (e, i) => t(e, "default" !== e ? i : {
    createHTML: t => t,
    createScript: t => t,
    createScriptURL: t => t
  });
}
```

**Attack chain:**
```
cs.js auto-injects into EVERY page at document_start
    → Sets up postMessage bridge (no origin validation)
    → Injects nj.js + nj-engine.js into page MAIN world
    → Disables Trusted Types (weakens page's own DOM XSS protections)
    → Any page's JavaScript can now postMessage to the extension
    → Only check is spoofable: {$bus: true, appName: "__app_hrp"}
    → Attacker's ad/tracker/compromised script on ANY page can:
        - Call engine.executeJs → arbitrary code in any tab
        - Call store.getBgState → steal all credentials
        - Call netRules.register → MITM network traffic
    → No user interaction — happens on every page load
```

**Why this is zero-interaction:** The content script is declared in `manifest.json` with `"matches": ["*://*/*"]` and `"run_at": "document_start"`. Chrome auto-injects it into every page before any content loads. The user doesn't need to click the extension icon, open the popup, or interact in any way. Just browsing the web is enough.

---

## 3. Automatic Analytics Beacon to Mixpanel (HIGH)

**Trigger:** Automatic — fires on install, page navigation, and periodic events

**File:** `bg.js`

```javascript
// Fires automatically on extension install:
sendInstall() { this.send("install") }

// Fires automatically on every tab navigation:
sendPageview() { this.send("pageview", {domain: proxy.currentTabDomain}) }

// Sends to Mixpanel with hardcoded token:
fetch("https://api.mixpanel.com/track?ip=1", {
  method: "POST",
  headers: {"content-type": "application/json"},
  body: JSON.stringify(e)
})

// Token is hardcoded:
mixpanel: { token: "7958323a20a869de3c57712bfe521a6f" }
```

**Attack chain:**
```
Compromise Mixpanel account (token is public/hardcoded)
    → OR MITM api.mixpanel.com responses
    → Extension sends browsing data (domains visited) automatically
    → ip=1 parameter means Mixpanel also collects user's IP address
    → Attacker with Mixpanel access gets:
        - Every domain the user visits (sent automatically)
        - User's IP address
        - Extension usage patterns
        - Install/update events
    → No user interaction — fires on every page navigation
```

**Why this is zero-interaction:** Analytics events fire automatically via Chrome's tab event listeners. Every time the user navigates to a new page, `sendPageview` fires with the domain name. This happens in the background service worker without any user action toward the extension.

---

## 4. Automatic IP Address Detection (HIGH)

**Trigger:** Automatic — called during billing/location detection

**File:** `bg.js`

```javascript
// Fetches user's IP without any user action:
const e = await fetch("https://whatismyipaddress.com/");
const t = await e.text();
const n = /<p class="information">(.+?)<\/p>/g;
// Parses IP and location from HTML response
```

**Attack chain:**
```
Extension automatically fetches whatismyipaddress.com
    → Scrapes user's IP address and geolocation
    → Stored in extension state (billing.location)
    → If whatismyipaddress.com is compromised:
        - Injected HTML could exploit the regex parser
        - Crafted response could inject data into extension state
    → DNS hijack of whatismyipaddress.com → attacker controls response
    → No user interaction required
```

---

## 5. Periodic Alarm-Based Background Tasks (HIGH)

**Trigger:** Automatic — 15+ chrome.alarms run on fixed schedules

The extension registers **15+ periodic alarms** that execute automatically:

| Alarm Name | Interval | What It Does |
|-----------|----------|-------------|
| `feature.update` | Every 3 hours | Fetches remote config from api.harpa.ai |
| `runner.runJobs` | Every 1 minute | Executes scheduled automation tasks |
| `billing.sm` | Every 60 minutes | Processes billing/message quotas |
| `chat.dropOldChats` | Every 90 minutes | Cleans old chat data |
| `chat.dropEmptyChats` | Every 60 minutes | Cleans empty chats |
| `chat.dropOldLinks` | Every 90 minutes | Cleans old links |
| `backup.save` | Every 60 minutes | Saves data to IDB |
| `backup.dropIframe` | Periodic | Manages backup iframe |
| `journal.dropOldEvents` | Every 60 minutes | Cleans journal events |
| `library.cleanupDomains` | Every 24 hours | Cleans domain data |
| `netRules.cleanupTabRules` | Every 5 minutes | Manages network rules |
| `files.cleanup` | Every 60 minutes | Cleans temporary files |
| `creator.grid.maskApiKeys` | Every 15 minutes | Masks API keys |
| `runner.sleepTimer.alarm` | Every 1 minute | Manages sleep timers |

**Most critical: `runner.runJobs` (every 1 minute)**

```javascript
chrome.alarms.run(this._runJobs.bind(this), {
  name: "runner.runJobs",
  delayInMinutes: 1,
  periodInMinutes: 1,
  immediately: true      // ← runs IMMEDIATELY on startup
});
```

This alarm checks for scheduled tasks and executes them automatically. If the remote config (vector #1) can inject scheduled tasks, this becomes a **remote code execution** channel that fires every 60 seconds.

**Attack chain:**
```
Compromise api.harpa.ai → inject malicious scheduled task via /feature config
    → runner.runJobs picks it up within 60 seconds
    → Task executes with full extension privileges
    → Can call executeJs, netRules.register, cookies.get, etc.
    → Repeats every minute until task is removed
    → No user interaction — alarm fires automatically
```

---

## 6. Auto-Registration of Network Interception Rules (HIGH)

**Trigger:** Automatic — on extension startup

**File:** `bg.js`

```javascript
// Auto-registers net rules on init:
t.netRulesController = {
  async init() {
    const e = this._createUaRules();
    const t = this._createLangRules();
    await n.register([...e, ...t]);
  }
}
```

The extension automatically registers `chrome.declarativeNetRequest` session rules on startup to modify HTTP headers (User-Agent, Accept-Language) for automation tasks.

**Attack chain:**
```
Extension auto-registers declarativeNetRequest rules on startup
    → If remote config (vector #1) controls rule parameters:
        - Attacker injects rules that redirect requests
        - Attacker injects rules that modify response headers
        - Attacker strips security headers (HSTS, CSP, X-Frame-Options)
    → Rules apply to ALL browser network traffic
    → No user interaction — rules registered on service worker init
```

**Additionally**, the `netRules.register` message handler is exposed via the postMessage bridge (vector #2), meaning any compromised script on any page can register new network interception rules.

---

## 7. Offscreen Document + External Iframe Auto-Load (CRITICAL)

**Trigger:** Automatic — created by background service worker

**File:** `os.js`

```javascript
_createIframe() {
  const e = document.createElement("iframe");
  e.src = "https://harpa.ai/oi";
  e.name = `offscreen-iframe | ${chrome.runtime.getURL("/oi.js")}`;
  document.body.append(e);
}
```

The background service worker automatically creates an offscreen document which loads an iframe from `https://harpa.ai/oi`. This happens without any user interaction.

**Attack chain:**
```
bg.js auto-creates offscreen document on startup
    → os.js loads iframe from https://harpa.ai/oi
    → Compromise harpa.ai (server breach, DNS hijack, CDN MITM)
    → Malicious content loads in the iframe
    → Bidirectional postMessage bridge (no origin validation)
    → Attacker code runs inside extension's offscreen context
    → Full access to chrome.runtime.sendMessage
    → Can invoke ALL 117+ bg.js message handlers
    → No user interaction — iframe loads on extension startup
```

---

## 8. Automatic Trusted Types Disabling on Every Website (HIGH)

**Trigger:** Automatic — runs on every page via auto-injected content script

**File:** `bg.js` (called from cs.js initialization)

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

**Impact:** This automatically **removes DOM XSS protections** from every website the user visits. Websites that rely on Trusted Types for security (Google, GitHub, etc.) lose their protection.

**Attack chain:**
```
User visits any website with Trusted Types enabled
    → cs.js auto-injects at document_start
    → Patches trustedTypes.createPolicy to accept ANY input
    → Website's Trusted Types security policy is neutralized
    → DOM XSS attacks that would normally be blocked now succeed
    → Any third-party script on the page (ads, analytics, CDN)
      can exploit the weakened security
    → No user interaction — happens before page content loads
```

---

## 9. Chrome Auto-Update Mechanism (MEDIUM)

**Trigger:** Automatic — Chrome checks for updates every few hours

**File:** `manifest.json`

```json
"update_url": "https://clients2.google.com/service/update2/crx"
```

**Attack chain:**
```
Compromise HARPA's Chrome Web Store developer account
    → Push malicious extension update
    → Chrome auto-downloads and installs within hours
    → No user approval needed for same-permission updates
    → Malicious code runs immediately in bg.js service worker
    → Affects ALL 4M+ users within 24-48 hours
    → No user interaction — Chrome updates extensions silently
```

This is the standard Chrome extension update mechanism, but it means a **developer account compromise** is a fully zero-interaction supply chain attack.

---

## 10. OpenAI Content Script Auto-Injection (MEDIUM)

**Trigger:** Automatic — whenever user visits any OpenAI page

**File:** `manifest.json`

```json
{
  "matches": ["https://*.openai.com/*"],
  "js": ["/cs-openai.js"],
  "run_at": "document_start",
  "all_frames": true
}
```

A separate content script specifically targeting OpenAI pages auto-injects and runs before the page loads.

**Attack chain:**
```
User visits any openai.com page (for normal ChatGPT use)
    → cs-openai.js auto-injects at document_start
    → Has access to page DOM, cookies, session tokens
    → If cs-openai.js is compromised via extension update (vector #9)
      or remote config (vector #1):
        - Steal OpenAI session tokens
        - Intercept API keys entered in OpenAI dashboard
        - Modify ChatGPT responses
    → No user interaction with extension needed
```

---

## Zero-Interaction Attack Surface Summary

```
                    ZERO-INTERACTION ATTACK TIMELINE
                    =================================

CHROME LAUNCH (t=0):
    │
    ├── bg.js service worker starts automatically
    │     ├── controller.init() chain begins
    │     ├── feature.update: fetches api.harpa.ai/feature  ← VECTOR 1
    │     ├── Creates offscreen document → loads harpa.ai/oi iframe  ← VECTOR 7
    │     ├── Registers declarativeNetRequest rules  ← VECTOR 6
    │     ├── Sends install/startup analytics to Mixpanel  ← VECTOR 3
    │     ├── Fetches whatismyipaddress.com  ← VECTOR 4
    │     └── Starts 15+ chrome.alarms  ← VECTOR 5
    │
    ├── [Every 1 minute]: runner.runJobs executes scheduled tasks
    ├── [Every 3 hours]: feature.update re-fetches remote config
    ├── [Every 5 minutes]: netRules cleanup
    │
USER BROWSES ANY PAGE:
    │
    ├── cs.js auto-injects at document_start  ← VECTOR 2
    │     ├── Sets up postMessage bridge (no origin check)
    │     ├── Injects nj.js + nj-engine.js into MAIN world
    │     └── Disables Trusted Types  ← VECTOR 8
    │
    ├── [On OpenAI pages]: cs-openai.js auto-injects  ← VECTOR 10
    │
CHROME AUTO-UPDATE (background):
    │
    └── Silently installs new extension version  ← VECTOR 9
```

---

## Severity Matrix (Zero-Interaction Only)

| # | Vector | Severity | User Action Required | Auto-Trigger |
|---|--------|----------|---------------------|-------------|
| 1 | Remote config auto-fetch | **CRITICAL** | None | Chrome launch + every 3h |
| 2 | cs.js auto-injection on all pages | **CRITICAL** | None | Every page load |
| 3 | Mixpanel analytics beacon | HIGH | None | Every page navigation |
| 4 | IP address auto-detection | HIGH | None | Billing initialization |
| 5 | 15+ periodic alarm tasks | HIGH | None | Every 1-90 minutes |
| 6 | Auto-registered network rules | HIGH | None | Service worker init |
| 7 | External iframe auto-load | **CRITICAL** | None | Service worker init |
| 8 | Trusted Types auto-disable | HIGH | None | Every page load |
| 9 | Chrome silent auto-update | MEDIUM | None | Chrome's update cycle |
| 10 | OpenAI content script | MEDIUM | None | Any openai.com visit |

---

## Key Distinction from User-Interaction Vectors

The following vectors from the previous analysis were **excluded** because they require user action:

| Excluded Vector | Why Excluded |
|----------------|-------------|
| Webhook execution in tasks | Requires user to import/run a task |
| Community task import | Requires user to import a shared task |
| CDN load in harpa.html | Requires user to open extension popup |
| cs-web.js bridge | Requires user to visit harpa.ai specifically |

**All 10 vectors above require ZERO user interaction** — they execute automatically from the moment the extension is installed and Chrome is running.

---

## Recommended Remediations (Priority Order)

1. **Pin and validate remote config** — Add response schema validation, signature verification, and certificate pinning for `api.harpa.ai/feature` responses
2. **Eliminate external iframe** — Bundle `harpa.ai/oi` functionality locally in the extension instead of loading from external domain
3. **Add origin validation** to all `postMessage` listeners in `cs.js` — check `event.origin` against allowlist
4. **Stop disabling Trusted Types** — Remove `_patchTrustedTypes()` or make it opt-in per-site
5. **Reduce content script scope** — Change `"matches": ["*://*/*"]` to only domains where the extension needs to function
6. **Remove IP detection** — Eliminate the `whatismyipaddress.com` fetch or use server-side geolocation
7. **Proxy analytics server-side** — Remove hardcoded Mixpanel token, route analytics through HARPA's backend
8. **Enable 2FA and access controls** on Chrome Web Store developer account
9. **Reduce alarm frequency** — `runner.runJobs` every 1 minute is excessive; increase interval
10. **Audit bundled dependencies** — Create `package.json` tracking PDF.js, JSZip, MobX versions; enable CVE monitoring

---

*Analysis performed on HARPA AI Chrome Extension v9.8.0*
*Extension ID: eanggfilgoajaocelnaflolkadkeghjp*
*Date: 2026-03-05*
*Focus: Zero-interaction supply chain attack vectors only*
