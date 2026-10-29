
const AES_KEY_B64 = "kw63Ew8vpM3RpFVDKRetIXGCYPuhia9hjROytJSyAy0=";
const AES_IV_B64 = "MTIzNDU2Nzg5MDEyMzQ1Ng==";

const payloadInput = document.getElementById("payload");
const output = document.getElementById("output");
const status = document.getElementById("status");

document.getElementById("decryptBtn").addEventListener("click", () => {
  const input = payloadInput.value.trim();

  if (!input) {
    status.textContent = "Please paste an encrypted payload.";
    output.textContent = "";
    return;
  }

  try {
    // Decode URL-encoded ciphertext.
    const decoded = decodeURIComponent(input);

    // Match the Angular EncryptionService configuration.
    const key = CryptoJS.enc.Base64.parse(AES_KEY_B64);
    const iv = CryptoJS.enc.Base64.parse(AES_IV_B64);
    const ciphertext = CryptoJS.enc.Base64.parse(decoded);

    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext },
      key,
      {
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );

    const plaintext = decrypted.toString(CryptoJS.enc.Utf8);

    if (!plaintext) {
      throw new Error("Decryption returned empty text.");
    }

    // Parse and display formatted JSON.
    const data = JSON.parse(plaintext);

    output.textContent = JSON.stringify(data, null, 2);
    status.textContent = "Decryption successful.";
  } catch (error) {
    output.textContent = "";
    status.textContent =
      "Decryption failed. Check the payload, key, IV, and encryption format.";
    console.error("Decryption error:", error);
  }
});

document.getElementById("clearBtn").addEventListener("click", () => {
  payloadInput.value = "";
  output.textContent = "";
  status.textContent = "";
});

document.getElementById("copyBtn").addEventListener("click", async () => {
  const text = output.textContent;

  if (!text || text === "Your decrypted JSON will appear here.") {
    status.textContent = "There is no decrypted output to copy.";
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    status.textContent = "Decrypted JSON copied.";
  } catch {
    status.textContent = "Copy failed. Select and copy the output manually.";
  }
});
