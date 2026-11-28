// service-worker.js
// Manifest V3 Background Service Worker
// Maintains isolated storage cleanup and message routing without static host permissions.

chrome.tabs.onRemoved.addListener((tabId) => {
  if (chrome.storage && chrome.storage.local) {
    chrome.storage.local.remove([`websiteScan_${tabId}`, `audit_${tabId}`]);
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !message.type) return false;

  if (message.type === "GET_CONFIG_URL") {
    chrome.storage.local.get(["managingUrl", "managingUrlStatus"], (res) => {
      sendResponse({
        managingUrl: res.managingUrl || null,
        health: res.managingUrlStatus || null
      });
    });
    return true;
  }

  if (message.type === "GET_ISOLATED_REPORTS") {
    chrome.storage.local.get(["lastWebsiteScan", "lastIotAudit"], (res) => {
      sendResponse({
        websiteScan: res.lastWebsiteScan || null,
        iotAudit: res.lastIotAudit || null
      });
    });
    return true;
  }

  return false;
});
