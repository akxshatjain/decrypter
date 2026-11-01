/* ==========================================================
   AES Studio — Bidirectional Encryptor / Decryptor
   AES-256-CBC | PKCS7 | URL-encoded Base64
   ========================================================== */

// Original encryption parameters — preserved.
const AES_KEY_B64 = "kw63Ew8vpM3RpFVDKRetIXGCYPuhia9hjROytJSyAy0=";
const AES_IV_B64 = "MTIzNDU2Nzg5MDEyMzQ1Ng==";

// DOM Elements
const payloadInput = document.getElementById("payload");
const charCount = document.getElementById("charCount");
const inputHint = document.getElementById("inputHint");
const dropZone = document.getElementById("dropZone");

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

const pasteModal = document.getElementById("pasteModal");
const closePasteModalBtn = document.getElementById("closePasteModalBtn");
const cancelPasteModalBtn = document.getElementById("cancelPasteModalBtn");
const applyPasteModalBtn = document.getElementById("applyPasteModalBtn");
const applyAndDecryptBtn = document.getElementById("applyAndDecryptBtn");
const modalPasteInput = document.getElementById("modalPasteInput");
const modalCharCount = document.getElementById("modalCharCount");
const modalFormatBadge = document.getElementById("modalFormatBadge");

// Application state
let rawOutput = "";
let parsedJsonObject = null;
let lastOperation = "";
let isMinified = false;
let toastTimeout = null;

// ==========================================================
// TOAST
// ==========================================================

function showToast(message, type = "success") {
    if (!statusToast) return;

    clearTimeout(toastTimeout);

    statusToast.textContent = message;
    statusToast.className = `toast-notification active ${type}`;

    toastTimeout = setTimeout(() => {
        statusToast.classList.remove("active");
    }, 2800);
}

// ==========================================================
// INPUT STATS
// ==========================================================

function updateInputStats() {
    if (!payloadInput) return;

    const value = payloadInput.value;
    const count = value.length;

    if (charCount) {
        charCount.textContent =
            `${count.toLocaleString()} character${count === 1 ? "" : "s"}`;
    }

    if (!inputHint) return;

    if (!value.trim()) {
        inputHint.textContent = "JSON or URL-encoded Base64";
        return;
    }

    try {
        JSON.parse(value);

        inputHint.textContent =
            "Valid JSON detected — ready to encrypt";

    } catch {
        inputHint.textContent =
            "Ciphertext detected as candidate — ready to decrypt";
    }
}

// ==========================================================
// AES KEY AND IV
// ==========================================================

function getAESParameters() {
    if (typeof CryptoJS === "undefined") {
        throw new Error(
            "CryptoJS is not loaded. Check your CryptoJS CDN script."
        );
    }

    const key = CryptoJS.enc.Base64.parse(AES_KEY_B64);
    const iv = CryptoJS.enc.Base64.parse(AES_IV_B64);

    if (key.sigBytes !== 32) {
        throw new Error("AES key must be 256 bits (32 bytes).");
    }

    if (iv.sigBytes !== 16) {
        throw new Error("AES-CBC IV must be 128 bits (16 bytes).");
    }

    return { key, iv };
}

// ==========================================================
// ENCRYPTION
// ==========================================================

function encryptPayload(jsonString) {
    const { key, iv } = getAESParameters();

    const encrypted = CryptoJS.AES.encrypt(
        CryptoJS.enc.Utf8.parse(jsonString),
        key,
        {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }
    );

    const base64Ciphertext =
        encrypted.ciphertext.toString(CryptoJS.enc.Base64);

    // Preserve the original URL-encoded Base64 format.
    return encodeURIComponent(base64Ciphertext);
}

// ==========================================================
// CIPHERTEXT NORMALIZATION
// ==========================================================

function normalizeCiphertext(input) {
    let value = input.trim();

    // Support URL-encoded Base64.
    if (value.includes("%")) {
        try {
            value = decodeURIComponent(value);
        } catch {
            throw new Error("Invalid URL-encoded ciphertext.");
        }
    }

    // Remove whitespace and line breaks.
    return value.replace(/\s+/g, "");
}

// ==========================================================
// DECRYPTION
// ==========================================================

function decryptCiphertext(input) {
    const { key, iv } = getAESParameters();

    const base64 = normalizeCiphertext(input);

    if (!base64) {
        throw new Error("Please enter encrypted ciphertext.");
    }

    // Validate Base64 characters.
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
        throw new Error(
            "Invalid ciphertext. Expected Base64 or URL-encoded Base64."
        );
    }

    const ciphertext = CryptoJS.enc.Base64.parse(base64);

    if (!ciphertext.sigBytes || ciphertext.sigBytes % 16 !== 0) {
        throw new Error(
            "Invalid AES ciphertext length. Check the input."
        );
    }

    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: ciphertext },
        key,
        {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }
    );

    let plaintext;

    try {
        plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    } catch {
        throw new Error(
            "Decryption failed. Check the AES key and IV."
        );
    }

    if (!plaintext) {
        throw new Error(
            "Unable to decrypt. The key, IV or ciphertext may be incorrect."
        );
    }

    try {
        return JSON.parse(plaintext);
    } catch {
        throw new Error(
            "Decryption completed, but the decrypted content is not valid JSON."
        );
    }
}

// ==========================================================
// HTML ESCAPING AND JSON HIGHLIGHTING
// ==========================================================

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function highlightJson(json) {
    const escaped = escapeHtml(json);

    return escaped.replace(
        /("(?:\\.|[^"\\])*"(?=\s*:))|("(?:\\.|[^"\\])*")|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]/g,

        (match, key, stringValue, booleanOrNull) => {
            if (key) {
                return `<span class="json-key">${key}</span>`;
            }

            if (stringValue) {
                return `<span class="json-string">${stringValue}</span>`;
            }

            if (booleanOrNull === "true" ||
                booleanOrNull === "false") {
                return `<span class="json-boolean">${match}</span>`;
            }

            if (booleanOrNull === "null") {
                return `<span class="json-null">${match}</span>`;
            }

            if (/^[{}\[\],:]$/.test(match)) {
                return `<span class="json-punct">${match}</span>`;
            }

            return `<span class="json-number">${match}</span>`;
        }
    );
}

// ==========================================================
// LINE GUTTER
// ==========================================================

function updateLineNumbers(text) {
    if (!lineGutter) return;

    const lines = text.split("\n");

    lineGutter.innerHTML = lines
        .map((_, index) =>
            `<span class="gutter-line">${index + 1}</span>`
        )
        .join("");
}

// ==========================================================
// OUTPUT RENDERING — DECRYPTED JSON
// ==========================================================

function renderDecryptedOutput(jsonString) {
    rawOutput = jsonString;
    lastOperation = "decrypt";

    if (outputCode) {
        outputCode.innerHTML = highlightJson(jsonString);
    }

    updateLineNumbers(jsonString);

    if (emptyState) emptyState.style.display = "none";
    if (errorBanner) errorBanner.style.display = "none";
    if (codeView) codeView.style.display = "flex";

    if (copyBtn) copyBtn.disabled = false;
    if (downloadBtn) downloadBtn.disabled = false;
    if (formatBtn) formatBtn.disabled = false;

    if (outputTag) {
        outputTag.textContent = "DECRYPTED";
        outputTag.className = "badge badge-success";
    }

    const lines = jsonString.split("\n").length;
    const size = (new Blob([jsonString]).size / 1024).toFixed(2);

    if (outputMeta) {
        outputMeta.textContent =
            `${lines} lines · ${size} KB · Valid JSON`;
    }

    if (outputFormatTag) {
        outputFormatTag.textContent = "JSON";
    }

    if (copyBtnText) {
        copyBtnText.textContent = "Copy JSON";
    }

    if (formatBtn) {
        const span = formatBtn.querySelector("span");
        if (span) span.textContent = "Minify";
    }
}

// ==========================================================
// OUTPUT RENDERING — ENCRYPTED TEXT
// ==========================================================

function renderEncryptedOutput(ciphertext) {
    rawOutput = ciphertext;
    lastOperation = "encrypt";

    parsedJsonObject = null;
    isMinified = false;

    if (outputCode) {
        // Use textContent for ciphertext, not HTML.
        outputCode.textContent = ciphertext;
    }

    updateLineNumbers(ciphertext);

    if (emptyState) emptyState.style.display = "none";
    if (errorBanner) errorBanner.style.display = "none";
    if (codeView) codeView.style.display = "flex";

    if (copyBtn) copyBtn.disabled = false;
    if (downloadBtn) downloadBtn.disabled = false;
    if (formatBtn) formatBtn.disabled = true;

    if (outputTag) {
        outputTag.textContent = "ENCRYPTED";
        outputTag.className = "badge badge-success";
    }

    const size = (new Blob([ciphertext]).size / 1024).toFixed(2);

    if (outputMeta) {
        outputMeta.textContent =
            `Encrypted successfully · ${size} KB`;
    }

    if (outputFormatTag) {
        outputFormatTag.textContent = "AES CIPHERTEXT";
    }

    if (copyBtnText) {
        copyBtnText.textContent = "Copy Ciphertext";
    }

    showToast("JSON encrypted successfully!", "success");
}

// ==========================================================
// RESET OUTPUT
// ==========================================================

function resetOutput() {
    rawOutput = "";
    parsedJsonObject = null;
    lastOperation = "";
    isMinified = false;

    if (emptyState) emptyState.style.display = "flex";
    if (codeView) codeView.style.display = "none";
    if (errorBanner) errorBanner.style.display = "none";

    if (outputTag) {
        outputTag.textContent = "AWAITING";
        outputTag.className = "badge";
    }

    if (outputMeta) {
        outputMeta.textContent = "Waiting for input";
    }

    if (outputFormatTag) {
        outputFormatTag.textContent = "JSON / TEXT";
    }

    if (copyBtn) copyBtn.disabled = true;
    if (downloadBtn) downloadBtn.disabled = true;
    if (formatBtn) formatBtn.disabled = true;

    resetCopyButton();
}

// ==========================================================
// ERROR HANDLING
// ==========================================================

function showError(message) {
    rawOutput = "";
    parsedJsonObject = null;
    lastOperation = "";

    if (emptyState) emptyState.style.display = "none";
    if (codeView) codeView.style.display = "none";
    if (errorBanner) errorBanner.style.display = "block";

    if (errorMessage) {
        errorMessage.textContent = message;
    }

    if (outputTag) {
        outputTag.textContent = "ERROR";
        outputTag.className = "badge";
    }

    if (outputMeta) {
        outputMeta.textContent = "Processing failed";
    }

    if (copyBtn) copyBtn.disabled = true;
    if (downloadBtn) downloadBtn.disabled = true;
    if (formatBtn) formatBtn.disabled = true;

    showToast(message, "error");
}

// ==========================================================
// AUTOMATIC ENCRYPT / DECRYPT PROCESSOR
// ==========================================================

async function processPayload() {
    if (!payloadInput) return;

    const input = payloadInput.value.trim();

    if (!input) {
        showToast("Please enter JSON or encrypted ciphertext.", "error");
        payloadInput.focus();
        return;
    }

    if (typeof CryptoJS === "undefined") {
        showError("CryptoJS library is not loaded. Check your internet connection and CDN script.");
        return;
    }

    const originalButtonContent = decryptBtn
        ? decryptBtn.innerHTML
        : "";

    if (decryptBtn) {
        decryptBtn.disabled = true;

        decryptBtn.innerHTML = `
            <svg width="15" height="15"
                 viewBox="0 0 24 24"
                 fill="none"
                 stroke="currentColor"
                 stroke-width="2"
                 style="animation: spin 1s linear infinite;">
                <path d="M21 12a9 9 0 1 1-6.219-8.56"></path>
            </svg>
            <span>Processing...</span>
        `;
    }

    const startTime = performance.now();

    try {
        let parsedInput;
        let isJson = false;

        // First, check whether the input is valid JSON.
        try {
            parsedInput = JSON.parse(input);
            isJson = true;
        } catch {
            isJson = false;
        }

        // CASE 1: JSON input — encrypt it.
        if (isJson) {
            const jsonString = JSON.stringify(parsedInput);
            const encrypted = encryptPayload(jsonString);

            renderEncryptedOutput(encrypted);

            const elapsed = Math.round(
                performance.now() - startTime
            );

            showToast(
                `Encryption completed in ${elapsed}ms`,
                "success"
            );

            return;
        }

        // CASE 2: Non-JSON input — decrypt it.
        const decryptedObject = decryptCiphertext(input);

        parsedJsonObject = decryptedObject;
        isMinified = false;

        const formattedJson = JSON.stringify(
            decryptedObject,
            null,
            2
        );

        renderDecryptedOutput(formattedJson);

        const elapsed = Math.round(
            performance.now() - startTime
        );

        showToast(
            `Decryption completed in ${elapsed}ms`,
            "success"
        );

    } catch (error) {
        console.error("AES processing error:", error);

        showError(
            error && error.message
                ? error.message
                : "Unable to process the input. Please check your data and AES configuration."
        );

    } finally {
        if (decryptBtn) {
            decryptBtn.disabled = false;
            decryptBtn.innerHTML = originalButtonContent;
        }
    }
}

// ==========================================================
// JSON PRETTIFY / MINIFY
// ==========================================================

function togglePrettify() {
    if (lastOperation !== "decrypt" ||
        parsedJsonObject === null) {
        return;
    }

    isMinified = !isMinified;

    const jsonString = isMinified
        ? JSON.stringify(parsedJsonObject)
        : JSON.stringify(parsedJsonObject, null, 2);

    renderDecryptedOutput(jsonString);

    if (formatBtn) {
        const span = formatBtn.querySelector("span");

        if (span) {
            span.textContent = isMinified
                ? "Prettify"
                : "Minify";
        }
    }
}

// ==========================================================
// COPY OUTPUT
// ==========================================================

function resetCopyButton() {
    if (!copyIcon || !copyBtnText) return;

    copyIcon.innerHTML = `
        <rect x="9" y="9" width="13" height="13" rx="2"></rect>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
    `;

    copyBtnText.textContent =
        lastOperation === "encrypt"
            ? "Copy Ciphertext"
            : "Copy JSON";
}

async function copyOutput() {
    if (!rawOutput) return;

    try {
        await navigator.clipboard.writeText(rawOutput);

    } catch {
        // Fallback for browsers where Clipboard API is unavailable.
        const textarea = document.createElement("textarea");

        textarea.value = rawOutput;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";

        document.body.appendChild(textarea);

        textarea.select();
        document.execCommand("copy");

        textarea.remove();
    }

    if (copyIcon) {
        copyIcon.innerHTML =
            '<polyline points="20 6 9 17 4 12"></polyline>';
    }

    if (copyBtnText) {
        copyBtnText.textContent = "Copied!";
    }

    showToast(
        lastOperation === "encrypt"
            ? "Encrypted ciphertext copied!"
            : "Decrypted JSON copied!",
        "success"
    );

    setTimeout(resetCopyButton, 2000);
}

// ==========================================================
// DOWNLOAD OUTPUT
// ==========================================================

function downloadOutput() {
    if (!rawOutput) return;

    const encrypted = lastOperation === "encrypt";

    const blob = new Blob(
        [rawOutput],
        {
            type: encrypted
                ? "text/plain;charset=utf-8"
                : "application/json;charset=utf-8"
        }
    );

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;

    anchor.download = encrypted
        ? `encrypted-payload-${Date.now()}.txt`
        : `decrypted-payload-${Date.now()}.json`;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);

    showToast(
        encrypted
            ? "Encrypted payload downloaded"
            : "Decrypted JSON downloaded",
        "success"
    );
}

// ==========================================================
// CLEAR WORKSPACE
// ==========================================================

function clearWorkspace() {
    if (payloadInput) {
        payloadInput.value = "";
    }

    updateInputStats();
    resetOutput();

    showToast("Workspace cleared", "success");

    if (payloadInput) {
        payloadInput.focus();
    }
}

// ==========================================================
// PASTE MODAL
// ==========================================================

function openPasteModal() {
    if (!pasteModal || !modalPasteInput) return;

    modalPasteInput.value = "";

    if (modalCharCount) {
        modalCharCount.textContent = "0 characters";
    }

    if (modalFormatBadge) {
        modalFormatBadge.textContent = "Awaiting paste";
        modalFormatBadge.className = "modal-meta-badge";
    }

    if (applyPasteModalBtn) {
        applyPasteModalBtn.disabled = true;
    }

    if (applyAndDecryptBtn) {
        applyAndDecryptBtn.disabled = true;
    }

    pasteModal.style.display = "flex";

    void pasteModal.offsetWidth;

    pasteModal.classList.add("active");
    pasteModal.setAttribute("aria-hidden", "false");

    document.body.classList.add("modal-open");

    setTimeout(() => modalPasteInput.focus(), 120);
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

    const value = modalPasteInput.value;
    const count = value.length;

    if (modalCharCount) {
        modalCharCount.textContent =
            `${count.toLocaleString()} character${count === 1 ? "" : "s"}`;
    }

    const hasContent = count > 0;

    if (applyPasteModalBtn) {
        applyPasteModalBtn.disabled = !hasContent;
    }

    if (applyAndDecryptBtn) {
        applyAndDecryptBtn.disabled = !hasContent;
    }

    if (!modalFormatBadge) return;

    if (!hasContent) {
        modalFormatBadge.textContent = "Awaiting paste";
        modalFormatBadge.className = "modal-meta-badge";
        return;
    }

    try {
        JSON.parse(value);

        modalFormatBadge.textContent = "JSON — Encrypt";
        modalFormatBadge.className =
            "modal-meta-badge badge-success";

    } catch {
        modalFormatBadge.textContent = "Ciphertext — Decrypt";
        modalFormatBadge.className =
            "modal-meta-badge badge-accent";
    }
}

function applyModalPaste(autoProcess = false) {
    if (!modalPasteInput || !payloadInput) return;

    const value = modalPasteInput.value.trim();

    if (!value) {
        showToast("Please paste your input first.", "error");
        modalPasteInput.focus();
        return;
    }

    payloadInput.value = value;

    updateInputStats();
    closePasteModal();

    if (autoProcess) {
        processPayload();
    } else {
        showToast("Input pasted successfully.", "success");
        payloadInput.focus();
    }
}

// ==========================================================
// CLIPBOARD PASTE
// ==========================================================

async function pasteFromClipboard() {
    if (navigator.clipboard &&
        typeof navigator.clipboard.readText === "function") {

        try {
            const text = await navigator.clipboard.readText();

            if (text && text.trim()) {
                payloadInput.value = text.trim();

                updateInputStats();

                showToast("Pasted from clipboard.", "success");

                payloadInput.focus();
                return;
            }

            showToast("Clipboard is empty.", "error");
            return;

        } catch (error) {
            console.warn("Clipboard access unavailable:", error);
        }
    }

    openPasteModal();
}

// ==========================================================
// THEME
// ==========================================================

function applyTheme(theme) {
    const isDark = theme === "dark";

    document.documentElement.dataset.theme = theme;

    if (themeToggle) {
        themeToggle.setAttribute(
            "aria-pressed",
            String(isDark)
        );

        themeToggle.setAttribute(
            "aria-label",
            isDark
                ? "Switch to light mode"
                : "Switch to dark mode"
        );
    }

    if (themeLabel) {
        themeLabel.textContent =
            isDark ? "Light mode" : "Dark mode";
    }

    const themeMeta = document.querySelector(
        'meta[name="theme-color"]'
    );

    if (themeMeta) {
        themeMeta.setAttribute(
            "content",
            isDark ? "#080c14" : "#f8fafc"
        );
    }
}

function toggleTheme() {
    const current =
        document.documentElement.dataset.theme;

    const next =
        current === "dark" ? "light" : "dark";

    applyTheme(next);

    try {
        localStorage.setItem("aes-studio-theme", next);
    } catch {
        // Local storage may be disabled.
    }
}

function initTheme() {
    let savedTheme = "light";

    try {
        savedTheme =
            localStorage.getItem("aes-studio-theme") || "light";
    } catch {
        // Use light theme as fallback.
    }

    applyTheme(savedTheme);
}

// ==========================================================
// DRAG AND DROP
// ==========================================================

function initDragAndDrop() {
    if (!dropZone) return;

    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, event => {
            event.preventDefault();
            dropZone.classList.add("drag-active");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, event => {
            event.preventDefault();
            dropZone.classList.remove("drag-active");
        });
    });

    dropZone.addEventListener("drop", event => {
        const files =
            event.dataTransfer && event.dataTransfer.files;

        if (!files || !files.length) return;

        const file = files[0];
        const reader = new FileReader();

        reader.onload = loadEvent => {
            payloadInput.value =
                String(loadEvent.target.result || "");

            updateInputStats();

            showToast(`Loaded ${file.name}`, "success");
        };

        reader.onerror = () => {
            showToast("Unable to read the selected file.", "error");
        };

        reader.readAsText(file);
    });
}

// ==========================================================
// EVENT LISTENERS
// ==========================================================

if (decryptBtn) {
    decryptBtn.addEventListener("click", processPayload);
}

if (clearBtn) {
    clearBtn.addEventListener("click", clearWorkspace);
}

if (pasteBtn) {
    pasteBtn.addEventListener("click", pasteFromClipboard);
}

if (copyBtn) {
    copyBtn.addEventListener("click", copyOutput);
}

if (downloadBtn) {
    downloadBtn.addEventListener("click", downloadOutput);
}

if (formatBtn) {
    formatBtn.addEventListener("click", togglePrettify);
}

if (themeToggle) {
    themeToggle.addEventListener("click", toggleTheme);
}

if (payloadInput) {
    payloadInput.addEventListener("input", updateInputStats);

    payloadInput.addEventListener("keydown", event => {
        if (
            (event.ctrlKey || event.metaKey) &&
            event.key === "Enter"
        ) {
            event.preventDefault();
            processPayload();
        }
    });
}

// Modal controls
if (closePasteModalBtn) {
    closePasteModalBtn.addEventListener(
        "click",
        closePasteModal
    );
}

if (cancelPasteModalBtn) {
    cancelPasteModalBtn.addEventListener(
        "click",
        closePasteModal
    );
}

if (applyPasteModalBtn) {
    applyPasteModalBtn.addEventListener(
        "click",
        () => applyModalPaste(false)
    );
}

if (applyAndDecryptBtn) {
    applyAndDecryptBtn.addEventListener(
        "click",
        () => applyModalPaste(true)
    );
}

if (modalPasteInput) {
    modalPasteInput.addEventListener(
        "input",
        updateModalStats
    );

    modalPasteInput.addEventListener(
        "paste",
        () => setTimeout(updateModalStats, 50)
    );

    modalPasteInput.addEventListener("keydown", event => {
        if (
            (event.ctrlKey || event.metaKey) &&
            event.key === "Enter"
        ) {
            event.preventDefault();
            applyModalPaste(true);
        }
    });
}

if (pasteModal) {
    pasteModal.addEventListener("click", event => {
        if (event.target === pasteModal) {
            closePasteModal();
        }
    });
}

document.addEventListener("keydown", event => {
    if (
        event.key === "Escape" &&
        pasteModal &&
        pasteModal.classList.contains("active")
    ) {
        closePasteModal();
    }
});

// Synchronize output gutter scrolling.
if (outputPre && lineGutter) {
    outputPre.addEventListener("scroll", () => {
        lineGutter.scrollTop = outputPre.scrollTop;
    });
}

// ==========================================================
// INITIALIZATION
// ==========================================================

initTheme();
initDragAndDrop();
updateInputStats();
resetOutput();