"use strict";
!function(){try{var e="undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:{},n=(new Error).stack;n&&(e._sentryDebugIds=e._sentryDebugIds||{},e._sentryDebugIds[n]="bdbc89d1-87ee-55b7-baba-fd9dd3ac7984")}catch(e){}}();

(() => {
var n=window.location.hostname.includes("dropbox")&&(window.location.pathname.includes("get")||window.location.search.includes("download_id"));window.hasWebauthnInjectionHelperRun!==!0&&!n&&o();function o(){window.hasWebauthnInjectionHelperRun=!0;let e=document.createElement("script");e.src=chrome.runtime.getURL("/inline/injected/webauthn-listeners.js"),document.documentElement.prepend(e),e.remove()}
})();

//# debugId=bdbc89d1-87ee-55b7-baba-fd9dd3ac7984
