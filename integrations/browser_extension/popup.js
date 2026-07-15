let currentUrl = null;

function hostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

async function initialize() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url && /^https?:\/\//i.test(tab.url)) currentUrl = tab.url;
  document.getElementById("target").textContent = currentUrl ? hostname(currentUrl) : "No scannable page";
  document.getElementById("scan").disabled = !currentUrl;
  const saved = await chrome.storage.local.get({ depth: "tier0" });
  document.getElementById("depth").value = saved.depth;
}

function render(result) {
  document.getElementById("result").hidden = false;
  document.getElementById("category").textContent = `${result.category} · ${result.decision}`;
  document.getElementById("risk").textContent = `${Math.round(result.risk_score * 100)}% risk`;
  const fill = document.getElementById("risk-fill");
  fill.style.width = `${Math.round(result.risk_score * 100)}%`;
  fill.style.background = result.decision === "block" ? "#b42318" : result.decision === "review" ? "#b54708" : "#067647";
  const reasons = document.getElementById("reasons");
  reasons.replaceChildren(...result.reasons.slice(0, 3).map((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    return item;
  }));
}

document.getElementById("scan").addEventListener("click", async () => {
  const button = document.getElementById("scan");
  const status = document.getElementById("status");
  button.disabled = true;
  status.textContent = "Scanning...";
  const depth = document.getElementById("depth").value;
  await chrome.storage.local.set({ depth });
  try {
    const response = await chrome.runtime.sendMessage({ type: "scan-url", url: currentUrl });
    if (!response?.ok) throw new Error(response?.error || "Scan failed");
    render(response.result);
    status.textContent = "";
  } catch (error) {
    status.textContent = String(error).replace(/^Error:\s*/, "");
  } finally {
    button.disabled = false;
  }
});

document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
initialize();

