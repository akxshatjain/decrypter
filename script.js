/**
 * AES Studio — Payload Decryptor
 * Client-side cryptographic processing engine and developer workbench.
 */

// Cryptographic Parameters
const AES_KEY_B64 = "kw63Ew8vpM3RpFVDKRetIXGCYPuhia9hjROytJSyAy0=";
const AES_IV_B64 = "MTIzNDU2Nzg5MDEyMzQ1Ng==";

// DOM Elements
const payloadInput = document.getElementById("payload");
const charCount = document.getElementById("charCount");
const inputHint = document.getElementById("inputHint");
const dropZone = document.getElementById("dropZone");
const dropOverlay = document.getElementById("dropOverlay");

const decryptBtn = document.getElementById("decryptBtn");
const clearBtn = document.getElementById("clearBtn");
const pasteBtn = document.getElementById("pasteBtn");

const copyBtn = document.getElementById("copyBtn");
const copyIcon = document.getElementById("copyIcon");
const copyBtnText = document.getElementById("copyBtnText");
const formatBtn = document.getElementById("formatBtn");
const downloadBtn = document.getElementById("downloadBtn");

const outputTag = document.getElementById("outputTag");
const outputMeta = document.getElementById("outputMeta");
const outputFormatTag = document.getElementById("outputFormatTag");

const emptyState = document.getElementById("emptyState");
const codeView = document.getElementById("codeView");
const outputPre = document.getElementById("output");
const outputCode = document.getElementById("outputCode");
const lineGutter = document.getElementById("lineGutter");

const errorBanner = document.getElementById("errorBanner");
const errorMessage = document.getElementById("errorMessage");

const statusToast = document.getElementById("status");
const themeToggle = document.getElementById("themeToggle");
const themeLabel = document.getElementById("themeLabel");

// Mobile & Fallback Paste Modal Elements
const pasteModal = document.getElementById("pasteModal");
const closePasteModalBtn = document.getElementById("closePasteModalBtn");
const cancelPasteModalBtn = document.getElementById("cancelPasteModalBtn");
const applyPasteModalBtn = document.getElementById("applyPasteModalBtn");
const applyAndDecryptBtn = document.getElementById("applyAndDecryptBtn");
const modalPasteInput = document.getElementById("modalPasteInput");
const modalCharCount = document.getElementById("modalCharCount");
const modalFormatBadge = document.getElementById("modalFormatBadge");

// State
let rawDecryptedJson = "";
let parsedJsonObject = null;
let isMinified = false;
let toastTimeout = null;

/**
 * Toast Notification System
 */
function showToast(message, type = "success") {
  if (!statusToast) return;

  clearTimeout(toastTimeout);
  statusToast.textContent = message;
  statusToast.className = `toast-notification active ${type}`;

  toastTimeout = setTimeout(() => {
    statusToast.classList.remove("active");
  }, 2600);
}

/**
 * Helper to update character counter and format indicator
 */
function updateInputStats() {
  const text = payloadInput.value;
  const count = text.length;

  charCount.textContent = `${count.toLocaleString()} character${count === 1 ? "" : "s"}`;

  if (count === 0) {
    inputHint.textContent = "Base64 format";
  } else if (text.includes("%")) {
    inputHint.textContent = "URL-Encoded detected";
  } else {
    inputHint.textContent = "Raw Base64 detected";
  }
}

/**
 * Native Web Crypto API Decryption Fallback
 * Works without any external CDN dependencies in modern browsers.
 */
async function decryptWithWebCrypto(ciphertextBytes) {
  const rawKey = Uint8Array.from(atob(AES_KEY_B64), (c) => c.charCodeAt(0));
  const rawIv = Uint8Array.from(atob(AES_IV_B64), (c) => c.charCodeAt(0));

  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-CBC", iv: rawIv },
    cryptoKey,
    ciphertextBytes
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Syntax Highlighting for JSON Output
 */
function highlightJson(json) {
  // Escape HTML entities to prevent injection
  const escaped = json
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Regex token matching for JSON syntax
  return escaped.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|[{}\[\],:])/g,
    (match) => {
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          // Key name
          return `<span class="json-key">${match.slice(0, -1)}</span><span class="json-punct">:</span>`;
        }
        // String value
        return `<span class="json-string">${match}</span>`;
      }
      if (/true|false/.test(match)) {
        return `<span class="json-boolean">${match}</span>`;
      }
      if (/null/.test(match)) {
        return `<span class="json-null">${match}</span>`;
      }
      if (/[{}\[\],:]/.test(match)) {
        return `<span class="json-punct">${match}</span>`;
      }
      return `<span class="json-number">${match}</span>`;
    }
  );
}

/**
 * Render Output with Line Numbers and Gutter
 */
function renderOutput(jsonString) {
  rawDecryptedJson = jsonString;

  // Build highlighted HTML
  outputCode.innerHTML = highlightJson(jsonString);

  // Compute lines for gutter
  const lines = jsonString.split("\n");
  let gutterHtml = "";
  for (let i = 1; i <= lines.length; i++) {
    gutterHtml += `<span class="gutter-line">${i}</span>`;
  }
  lineGutter.innerHTML = gutterHtml;

  // Update views
  emptyState.style.display = "none";
  errorBanner.style.display = "none";
  codeView.style.display = "flex";

  // Enable action buttons
  copyBtn.disabled = false;
  formatBtn.disabled = false;
  downloadBtn.disabled = false;

  // Update Metadata
  outputTag.textContent = "DECRYPTED";
  outputTag.className = "badge badge-success";

  const sizeKb = (new Blob([jsonString]).size / 1024).toFixed(2);
  outputMeta.textContent = `${lines.length} lines · ${sizeKb} KB · Valid JSON`;
  outputFormatTag.textContent = "JSON";
}

/**
 * Reset Output Area to Empty State
 */
function resetOutput() {
  rawDecryptedJson = "";
  parsedJsonObject = null;
  isMinified = false;

  emptyState.style.display = "flex";
  codeView.style.display = "none";
  errorBanner.style.display = "none";

  outputTag.textContent = "AWAITING";
  outputTag.className = "badge";

  outputMeta.textContent = "Waiting for input";
  copyBtn.disabled = true;
  formatBtn.disabled = true;
  downloadBtn.disabled = true;

  resetCopyButton();
}

/**
 * Show Decryption Error State
 */
function showError(message) {
  rawDecryptedJson = "";
  parsedJsonObject = null;

  emptyState.style.display = "none";
  codeView.style.display = "none";
  errorBanner.style.display = "block";
  errorMessage.textContent = message;

  outputTag.textContent = "ERROR";
  outputTag.className = "badge";
  outputMeta.textContent = "Decryption failed";

  copyBtn.disabled = true;
  formatBtn.disabled = true;
  downloadBtn.disabled = true;

  showToast(message, "error");
}

/**
 * Core Decryption Dispatcher
 */
async function decryptPayload() {
  const input = payloadInput.value.trim();

  if (!input) {
    showToast("Please enter an encrypted payload to decrypt.", "error");
    payloadInput.focus();
    return;
  }

  // Visual button loading state
  decryptBtn.disabled = true;
  const originalBtnHtml = decryptBtn.innerHTML;
  decryptBtn.innerHTML = `
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite;">
      <path d="M21 12a9 9 0 1 1-6.219-8.56"></path>
    </svg>
    <span>Decrypting…</span>
  `;

  const startTime = performance.now();

  try {
    // 1. URL Decode the input
    let decodedString = input;
    try {
      decodedString = decodeURIComponent(input);
    } catch {
      // Input wasn't URL encoded or already decoded
    }

    let plaintext = "";

    // 2. Try CryptoJS if available
    if (typeof CryptoJS !== "undefined") {
      const key = CryptoJS.enc.Base64.parse(AES_KEY_B64);
      const iv = CryptoJS.enc.Base64.parse(AES_IV_B64);
      const ciphertext = CryptoJS.enc.Base64.parse(decodedString);

      const decrypted = CryptoJS.AES.decrypt({ ciphertext }, key, {
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    } else if (window.crypto && window.crypto.subtle) {
      // Fallback to Native Web Crypto API
      const binaryString = atob(decodedString);
      const bytes = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
      plaintext = await decryptWithWebCrypto(bytes);
    } else {
      throw new Error("No cryptographic engine available in this browser environment.");
    }

    if (!plaintext) {
      throw new Error("Decryption returned empty content. Verify the key and IV match.");
    }

    // 3. Parse JSON to validate payload structure
    const parsed = JSON.parse(plaintext);
    parsedJsonObject = parsed;
    isMinified = false;

    const formattedJson = JSON.stringify(parsed, null, 2);
    renderOutput(formattedJson);

    const elapsed = Math.round(performance.now() - startTime);
    showToast(`Decrypted in ${elapsed}ms`, "success");
  } catch (err) {
    console.error("AES Decryption error:", err);
    showError(
      err.message ||
        "Could not decrypt this payload. Verify ciphertext, AES-256 key, IV, and PKCS7 padding."
    );
  } finally {
    decryptBtn.disabled = false;
    decryptBtn.innerHTML = originalBtnHtml;
  }
}

/**
 * Toggle Format / Minify JSON
 */
function togglePrettify() {
  if (!parsedJsonObject) return;

  isMinified = !isMinified;
  const nextJson = isMinified
    ? JSON.stringify(parsedJsonObject)
    : JSON.stringify(parsedJsonObject, null, 2);

  renderOutput(nextJson);
  formatBtn.querySelector("span").textContent = isMinified ? "Expand" : "Prettify";
}

/**
 * Download Decrypted JSON
 */
function downloadJson() {
  if (!rawDecryptedJson) return;

  const blob = new Blob([rawDecryptedJson], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `decrypted-payload-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast("Downloaded decrypted JSON file", "success");
}

/**
 * Reset Copy Button State
 */
function resetCopyButton() {
  if (!copyBtn) return;
  copyIcon.innerHTML = `
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
  `;
  copyBtnText.textContent = "Copy JSON";
}

/**
 * Copy JSON to Clipboard with Feedback
 */
async function copyOutput() {
  if (!rawDecryptedJson) return;

  try {
    await navigator.clipboard.writeText(rawDecryptedJson);
  } catch {
    // Fallback
    const temp = document.createElement("textarea");
    temp.value = rawDecryptedJson;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    document.body.appendChild(temp);
    temp.select();
    document.execCommand("copy");
    temp.remove();
  }

  // Visual success feedback
  copyIcon.innerHTML = `<polyline points="20 6 9 17 4 12"></polyline>`;
  copyBtnText.textContent = "Copied!";
  showToast("Decrypted JSON copied to clipboard", "success");

  setTimeout(resetCopyButton, 2000);
}

/**
 * Paste Modal Lifecycle & Mobile Support
 */
function openPasteModal() {
  if (!pasteModal || !modalPasteInput) return;

  modalPasteInput.value = "";
  if (modalCharCount) modalCharCount.textContent = "0 characters";
  if (modalFormatBadge) {
    modalFormatBadge.textContent = "Awaiting paste";
    modalFormatBadge.className = "modal-meta-badge";
  }
  if (applyPasteModalBtn) applyPasteModalBtn.disabled = true;
  if (applyAndDecryptBtn) applyAndDecryptBtn.disabled = true;

  pasteModal.style.display = "flex";
  void pasteModal.offsetWidth; // Force layout reflow for animation
  pasteModal.classList.add("active");
  pasteModal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");

  // Focus modal textarea so mobile keyboard / clipboard suggestion appears
  setTimeout(() => {
    modalPasteInput.focus();
  }, 120);
}

function closePasteModal() {
  if (!pasteModal) return;

  pasteModal.classList.remove("active");
  pasteModal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");

  setTimeout(() => {
    pasteModal.style.display = "none";
  }, 220);
}

function updateModalStats() {
  if (!modalPasteInput) return;
  const val = modalPasteInput.value;
  const count = val.length;

  if (modalCharCount) {
    modalCharCount.textContent = `${count.toLocaleString()} character${count === 1 ? "" : "s"}`;
  }

  const hasContent = count > 0;
  if (applyPasteModalBtn) applyPasteModalBtn.disabled = !hasContent;
  if (applyAndDecryptBtn) applyAndDecryptBtn.disabled = !hasContent;

  if (modalFormatBadge) {
    if (!hasContent) {
      modalFormatBadge.textContent = "Awaiting paste";
      modalFormatBadge.className = "modal-meta-badge";
    } else if (val.includes("%")) {
      modalFormatBadge.textContent = "URL-Encoded";
      modalFormatBadge.className = "modal-meta-badge badge-accent";
    } else {
      modalFormatBadge.textContent = "Base64";
      modalFormatBadge.className = "modal-meta-badge badge-success";
    }
  }
}

function applyModalPaste(autoDecrypt = false) {
  if (!modalPasteInput) return;

  const text = modalPasteInput.value.trim();
  if (!text) {
    showToast("Please paste your ciphertext first", "error");
    modalPasteInput.focus();
    return;
  }

  payloadInput.value = text;
  updateInputStats();
  closePasteModal();

  if (autoDecrypt) {
    showToast("Pasted payload. Decrypting…", "success");
    decryptPayload();
  } else {
    showToast("Payload pasted successfully", "success");
    payloadInput.focus();
  }
}

/**
 * Paste from Clipboard (Robust cross-platform & mobile support)
 */
async function pasteFromClipboard() {
  // 1. Try modern Asynchronous Clipboard API (works on HTTPS / localhost)
  if (navigator.clipboard && typeof navigator.clipboard.readText === "function") {
    try {
      const text = await navigator.clipboard.readText();
      if (text && text.trim()) {
        payloadInput.value = text.trim();
        updateInputStats();
        showToast("Pasted payload from clipboard", "success");
        payloadInput.focus();
        return;
      } else if (text !== undefined && text.trim() === "") {
        showToast("Clipboard is empty", "error");
        return;
      }
    } catch (err) {
      console.warn("Async clipboard readText rejected or blocked:", err);
      // Fall through to fallback
    }
  }

  // 2. Try document.execCommand('paste') fallback
  try {
    payloadInput.focus();
    payloadInput.select();
    const successful = document.execCommand("paste");
    if (successful && payloadInput.value.trim()) {
      updateInputStats();
      showToast("Pasted payload from clipboard", "success");
      return;
    }
  } catch {
    // execCommand fallback restricted in modern browsers; fall through
  }

  // 3. Mobile / Insecure context / Permission-denied Fallback: Open friendly bottom sheet
  openPasteModal();
}


/**
 * Clear Workspace
 */
function clearWorkspace() {
  payloadInput.value = "";
  updateInputStats();
  resetOutput();
  showToast("Workspace cleared", "success");
  payloadInput.focus();
}

/**
 * Theme Management
 */
function applyTheme(theme) {
  const isDark = theme === "dark";
  document.documentElement.dataset.theme = theme;

  themeToggle.setAttribute("aria-pressed", String(isDark));
  themeToggle.setAttribute(
    "aria-label",
    isDark ? "Switch to light mode" : "Switch to dark mode"
  );
  themeLabel.textContent = isDark ? "Light mode" : "Dark mode";

  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", isDark ? "#080c14" : "#f8fafc");
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme;
  const next = current === "dark" ? "light" : "dark";

  applyTheme(next);

  try {
    localStorage.setItem("aes-studio-theme", next);
  } catch {
    // Storage access restricted
  }
}

function initTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem("aes-studio-theme");
  } catch {
    // Storage access restricted
  }

  // Default theme is light when opening the page
  applyTheme(saved || "light");
}

/**
 * Drag and Drop Support
 */
function initDragAndDrop() {
  if (!dropZone) return;

  ["dragenter", "dragover"].forEach((event) => {
    dropZone.addEventListener(event, (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-active");
    });
  });

  ["dragleave", "drop"].forEach((event) => {
    dropZone.addEventListener(event, (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-active");
    });
  });

  dropZone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        payloadInput.value = event.target.result;
        updateInputStats();
        showToast(`Loaded "${file.name}"`, "success");
      };
      reader.readAsText(file);
    }
  });
}

/**
 * Synchronize Gutter Scroll with Output Scroll
 */
outputPre.addEventListener("scroll", () => {
  lineGutter.scrollTop = outputPre.scrollTop;
});

// Event Listeners
decryptBtn.addEventListener("click", decryptPayload);
clearBtn.addEventListener("click", clearWorkspace);
copyBtn.addEventListener("click", copyOutput);
pasteBtn.addEventListener("click", pasteFromClipboard);
formatBtn.addEventListener("click", togglePrettify);
downloadBtn.addEventListener("click", downloadJson);
themeToggle.addEventListener("click", toggleTheme);

payloadInput.addEventListener("input", updateInputStats);

// Keyboard shortcuts
payloadInput.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    e.preventDefault();
    decryptPayload();
  }
});

// Modal Event Listeners
closePasteModalBtn?.addEventListener("click", closePasteModal);
cancelPasteModalBtn?.addEventListener("click", closePasteModal);
applyPasteModalBtn?.addEventListener("click", () => applyModalPaste(false));
applyAndDecryptBtn?.addEventListener("click", () => applyModalPaste(true));

modalPasteInput?.addEventListener("input", updateModalStats);
modalPasteInput?.addEventListener("paste", () => setTimeout(updateModalStats, 50));
modalPasteInput?.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    e.preventDefault();
    applyModalPaste(true);
  }
});

pasteModal?.addEventListener("click", (e) => {
  if (e.target === pasteModal) {
    closePasteModal();
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && pasteModal?.classList.contains("active")) {
    closePasteModal();
  }
});

// Keyframes helper for button spinner
const styleSheet = document.createElement("style");
styleSheet.textContent = `@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`;
document.head.appendChild(styleSheet);

// Initial Setup
initTheme();
initDragAndDrop();
updateInputStats();
resetOutput();
