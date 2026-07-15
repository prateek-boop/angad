const DEFAULTS = {
  apiUrl: "http://127.0.0.1:8000",
  apiKey: "",
  depth: "tier0"
};

async function settings() {
  return chrome.storage.local.get(DEFAULTS);
}

async function scanUrl(url) {
  const config = await settings();
  const headers = { "Content-Type": "application/json" };
  if (config.apiKey) headers["X-API-Key"] = config.apiKey;
  const response = await fetch(`${config.apiUrl.replace(/\/$/, "")}/api/v1/scan`, {
    method: "POST",
    headers,
    body: JSON.stringify({ url, depth: config.depth })
  });
  if (!response.ok) throw new Error(`ShieldNet returned HTTP ${response.status}`);
  return response.json();
}

function setBadge(tabId, result) {
  const blocked = result.decision === "block";
  chrome.action.setBadgeText({ tabId, text: blocked ? "!" : result.decision === "review" ? "?" : "OK" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: blocked ? "#B42318" : result.decision === "review" ? "#B54708" : "#067647" });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "shieldnet-scan",
    title: "Scan with ShieldNet",
    contexts: ["page", "link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.linkUrl || info.pageUrl;
  if (!url || !/^https?:\/\//i.test(url)) return;
  try {
    const result = await scanUrl(url);
    await chrome.storage.session.set({ lastResult: result, lastUrl: url });
    if (tab?.id !== undefined) setBadge(tab.id, result);
  } catch (error) {
    if (tab?.id !== undefined) {
      chrome.action.setBadgeText({ tabId: tab.id, text: "ERR" });
      chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: "#475467" });
    }
    await chrome.storage.session.set({ lastError: String(error) });
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "scan-url") return false;
  scanUrl(message.url)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

