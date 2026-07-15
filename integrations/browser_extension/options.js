const DEFAULTS = { apiUrl: "http://127.0.0.1:8000", apiKey: "" };

async function load() {
  const settings = await chrome.storage.local.get(DEFAULTS);
  document.getElementById("api-url").value = settings.apiUrl;
  document.getElementById("api-key").value = settings.apiKey;
}

document.getElementById("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const apiUrl = document.getElementById("api-url").value.replace(/\/$/, "");
  const apiKey = document.getElementById("api-key").value;
  await chrome.storage.local.set({ apiUrl, apiKey });
  document.getElementById("status").textContent = "Saved";
});

load();

