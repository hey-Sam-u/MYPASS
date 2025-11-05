document.addEventListener("DOMContentLoaded", () => {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "index.html";
    return;
  }

  // Use 'Bearer <token>' header (common standard)
  fetch("http://localhost:5000/api/dashboard", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  })
    .then(async (res) => {
      if (!res.ok) {
        // unauthorized or expired token
        localStorage.removeItem("token");
        window.location.href = "index.html";
        return;
      }
      return res.json();
    })
    .then((data) => {
      if (!data) return;
      // set UI safely
      const welcomeEl = document.querySelector(".welcome-text");
      const emailEl = document.querySelector(".email-text");
      if (welcomeEl) welcomeEl.textContent = data.message || `Welcome`;
      if (emailEl) emailEl.textContent = data.email || "";
    })
    .catch((err) => {
      console.error("Dashboard fetch error:", err);
      localStorage.removeItem("token");
      window.location.href = "index.html";
    });

  // Logout
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      localStorage.removeItem("token");
      window.location.href = "index.html";
    });
  }
});

/* ===== Upload + client-side encryption helpers ===== */

// util: base64 encode
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

// derive a CryptoKey from passphrase using PBKDF2
async function deriveKeyFromPassphrase(passphrase, saltBytes) {
  const enc = new TextEncoder();
  const passKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 150000,
      hash: "SHA-256",
    },
    passKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// encrypt ArrayBuffer with AES-GCM
async function encryptArrayBuffer(key, iv, arrayBuffer) {
  const cipher = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    arrayBuffer
  );
  return new Uint8Array(cipher);
}

// UI wiring
(function initUploadUI() {
  const dropArea = document.getElementById("drop-area");
  const fileInput = document.getElementById("file-input");
  const uploadList = document.getElementById("upload-list");
  const recentStatus = document.getElementById("recent-status");

  let pendingFiles = []; // {file, element}

  // drag events
  ["dragenter", "dragover"].forEach((ev) => {
    dropArea.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropArea.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((ev) => {
    dropArea.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropArea.classList.remove("dragover");
    });
  });

  dropArea.addEventListener("drop", (e) => {
    const files = Array.from(e.dataTransfer.files || []);
    handleFiles(files);
  });

  fileInput.addEventListener("change", (e) => {
    const files = Array.from(e.target.files || []);
    handleFiles(files);
    fileInput.value = ""; // reset
  });

  function handleFiles(files) {
    files.forEach((file) => {
      const el = renderUploadItem(file);
      pendingFiles.push({ file, el });
    });
    // open passphrase modal
    showPassphraseModal(async (passphrase) => {
      // derive key and start uploads
      for (const item of pendingFiles) {
        await processAndUploadFile(item.file, passphrase, item.el);
      }
      pendingFiles = [];
    });
  }

  function renderUploadItem(file) {
    const div = document.createElement("div");
    div.className = "upload-item";
    div.innerHTML = `
      <div class="meta">
        <strong>${
          file.name
        }</strong> <span style="opacity:.8; font-size:.9rem;">• ${Math.round(
      file.size / 1024
    )} KB</span>
      </div>
      <div style="display:flex; align-items:center; gap:10px;">
        <div class="progress"><i></i></div>
        <div class="meta" style="min-width:60px; text-align:right;">Queued</div>
      </div>
    `;
    uploadList.prepend(div);
    return div;
  }

  async function processAndUploadFile(file, passphrase, itemEl) {
    try {
      itemEl.querySelector(".meta[style]").textContent = "Encrypting...";

      // generate per-file salt and iv
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(12));

      // derive AES-GCM key
      const key = await deriveKeyFromPassphrase(passphrase, salt);

      // read file as arrayBuffer
      const arrayBuffer = await file.arrayBuffer();

      // encrypt
      const cipherBytes = await encryptArrayBuffer(key, iv, arrayBuffer);

      // create blob and formData
      const encBlob = new Blob([cipherBytes], {
        type: "application/octet-stream",
      });
      const form = new FormData();
      form.append("file", encBlob, file.name + ".enc");
      form.append("filename_original", file.name);
      form.append("mime_type", file.type || "application/octet-stream");
      form.append("size_bytes", file.size);
      form.append("salt", bufToBase64(salt));
      form.append("iv", bufToBase64(iv));

      // show uploading UI
      itemEl.querySelector(".meta[style]").textContent = "Uploading...";
      const progressBar = itemEl.querySelector(".progress > i");

      // send to server
      const token = localStorage.getItem("token") || "";
      const res = await fetch("http://localhost:5000/api/upload", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: form,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ msg: "Upload failed" }));
        itemEl.querySelector(".meta[style]").textContent =
          err.msg || "Upload failed";
        recentStatus.textContent = `Upload failed: ${file.name}`;
        return;
      }

      const data = await res.json();
      itemEl.querySelector(".meta[style]").textContent = "Done";
      progressBar.style.width = "100%";
      recentStatus.textContent = `Uploaded ${file.name}`;

      // optionally refresh file list (if you implement /api/files)
      if (typeof refreshFileList === "function") refreshFileList();
    } catch (err) {
      console.error("Encrypt/upload error:", err);
      itemEl.querySelector(".meta[style]").textContent = "Error";
      recentStatus.textContent = `Error uploading ${file.name}`;
    }
  }

  // passphrase modal flow
  const modal = document.getElementById("passphrase-modal");
  const passInput = document.getElementById("passphrase-input");
  const passOk = document.getElementById("passphrase-ok");
  const passCancel = document.getElementById("passphrase-cancel");

  function showPassphraseModal(cb) {
    modal.classList.remove("hidden");
    passInput.value = "";
    passInput.focus();

    function clean() {
      modal.classList.add("hidden");
      passOk.removeEventListener("click", onOk);
      passCancel.removeEventListener("click", onCancel);
    }

    function onOk() {
      const pass = passInput.value.trim();
      if (!pass) {
        passInput.focus();
        return;
      }
      clean();
      cb(pass);
    }
    function onCancel() {
      clean();
      // clear pending UI items
      uploadList.querySelectorAll(".upload-item").forEach((el) => el.remove());
      pendingFiles = [];
    }

    passOk.addEventListener("click", onOk);
    passCancel.addEventListener("click", onCancel);
  }
})();

// === Fetch and show user files ===
async function loadFiles() {
  try {
    const token = localStorage.getItem("token");
    const res = await fetch("http://localhost:5000/api/files", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    const container = document.getElementById("file-list");
    container.innerHTML = ""; // clear old list

    if (data.files && data.files.length > 0) {
      data.files.forEach((file) => {
        const fileEl = document.createElement("div");
        fileEl.classList.add("file-item");
        fileEl.innerHTML = `
          <div class="file-info">
            <p class="file-name">${file.filename_original}</p>
            <p class="file-meta">${file.file_type.toUpperCase()} • ${(
          file.size_bytes / 1024
        ).toFixed(1)} KB • ${new Date(
          file.uploaded_at
        ).toLocaleDateString()}</p>
          </div>
          <div class="file-actions">
            <button class="btn-view" data-id="${file.id}">View</button>
            <button class="btn-download" data-id="${file.id}">Download</button>
            <button class="btn-delete" data-id="${file.id}">Delete</button>
          </div>
        `;
        container.appendChild(fileEl);
      });
    } else {
      container.innerHTML = `<p class="no-files">No files uploaded yet.</p>`;
    }
  } catch (err) {
    console.error("Error loading files:", err);
  }
}

// Call immediately when dashboard loads
loadFiles();

//delete btn click and file delete code with custome popup
// ===== Custom Popup Utility Functions =====

// Create popup dynamically
function showPopup(type, message, options = {}) {
  const popupContainer = document.getElementById("popup-container");

  // Create popup box
  const popup = document.createElement("div");
  popup.className = `popup ${type}`;
  popup.innerHTML = `
    <p>${message}</p>
    ${
      type === "confirm"
        ? `<div class="popup-actions">
             <button class="popup-btn yes-btn">Yes</button>
             <button class="popup-btn cancel-btn">Cancel</button>
           </div>`
        : ""
    }
  `;

  popupContainer.appendChild(popup);

  // Trigger animation
  setTimeout(() => popup.classList.add("show"), 10);

  // Auto remove for success/error
  if (type !== "confirm") {
    setTimeout(() => {
      popup.classList.remove("show");
      setTimeout(() => popup.remove(), 500);
    }, options.duration || 4500);
  }

  // For confirm popup — return promise
  if (type === "confirm") {
    return new Promise((resolve) => {
      popup.querySelector(".yes-btn").addEventListener("click", () => {
        popup.classList.remove("show");
        setTimeout(() => popup.remove(), 300);
        resolve(true);
      });
      popup.querySelector(".cancel-btn").addEventListener("click", () => {
        popup.classList.remove("show");
        setTimeout(() => popup.remove(), 300);
        resolve(false);
      });
    });
  }
}

// ===== Delete File Logic =====
document.addEventListener("click", async (e) => {
  if (e.target.classList.contains("btn-delete")) {
    const fileId = e.target.getAttribute("data-id");
    const token = localStorage.getItem("token");

    // Custom confirm popup
    const confirmed = await showPopup(
      "confirm",
      "Are you sure you want to delete this file?"
    );
    if (!confirmed) return;

    try {
      const res = await fetch(`http://localhost:5000/api/files/${fileId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });

      const data = await res.json();

      if (res.ok) {
        e.target.closest(".file-item").remove();
        showPopup("success", "File deleted successfully ✅");
      } else {
        showPopup("error", data.msg || "Failed to delete file ❌");
      }
    } catch (err) {
      console.error("Delete error:", err);
      showPopup("error", "Server error while deleting file ⚠️");
    }
  }
});
// ===== VIEW button: fetch metadata, ask passphrase, fetch encrypted blob, decrypt, preview =====
document.addEventListener("click", async (e) => {
  if (!e.target.classList.contains("btn-view")) return;

  const fileId = e.target.getAttribute("data-id");
  const token = localStorage.getItem("token");
  const modal = document.getElementById("file-preview-modal");
  const content = modal.querySelector(".file-preview-content");

  // 1) Fetch metadata (salt, iv, mime, name)
  try {
    const metaRes = await fetch(
      `http://localhost:5000/api/files/${fileId}/meta`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    if (!metaRes.ok) {
      content.innerHTML = `<p style="color:red;">Cannot get file info (${metaRes.status})</p>`;
      modal.classList.add("show");
      return;
    }
    const meta = await metaRes.json();

    // show modal loading
    modal.classList.add("show");
    content.innerHTML = `<p class="preview-loading">Loading...</p>`;

    // 🔒 show custom passphrase modal (instead of default prompt)
    const passModal = document.createElement("div");
    passModal.className = "passphrase-popup";
    passModal.innerHTML = `
      <div class="passphrase-popup-content slide-up">
        <h3>Enter passphrase to decrypt</h3>
        <input type="password" id="decrypt-pass" placeholder="Enter passphrase..." />
        <div class="popup-actions">
          <button id="decrypt-cancel">Cancel</button>
          <button id="decrypt-go">Decrypt</button>
        </div>
      </div>
    `;
    document.body.appendChild(passModal);
    const input = passModal.querySelector("#decrypt-pass");
    input.focus();

    const passphrase = await new Promise((resolve) => {
      passModal
        .querySelector("#decrypt-cancel")
        .addEventListener("click", () => {
          passModal.remove();
          resolve(null);
        });
      passModal.querySelector("#decrypt-go").addEventListener("click", () => {
        const val = input.value.trim();
        passModal.remove();
        resolve(val || null);
      });
    });

    if (!passphrase) {
      modal.classList.remove("show");
      return;
    }

    // 3) derive key using salt from meta
    const saltBuf = base64ToBuf(meta.salt);
    const key = await deriveKeyFromPassphrase(passphrase, saltBuf);

    // 4) fetch encrypted blob
    const fileRes = await fetch(`http://localhost:5000/api/files/${fileId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!fileRes.ok) {
      content.innerHTML = `<p style="color:red;">Failed to download encrypted file (${fileRes.status})</p>`;
      return;
    }
    const encArrayBuffer = await fileRes.arrayBuffer();

    // 5) decrypt
    try {
      const ivBuf = base64ToBuf(meta.iv);
      const plainBuf = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBuf },
        key,
        encArrayBuffer
      );

      const outBlob = new Blob([plainBuf], {
        type: meta.mime_type || "application/octet-stream",
      });

      // handle preview by type
      if ((meta.mime_type || "").startsWith("image/")) {
        const imgURL = URL.createObjectURL(outBlob);
        content.innerHTML = `<img src="${imgURL}" alt="Preview" />`;
      } else if ((meta.mime_type || "") === "application/pdf") {
        const pdfURL = URL.createObjectURL(outBlob);
        content.innerHTML = `<iframe src="${pdfURL}" title="PDF Preview"></iframe>`;
      } else if ((meta.mime_type || "").startsWith("text/")) {
        const text = await outBlob.text();
        content.innerHTML = `<pre style="text-align:left; white-space:pre-wrap;">${escapeHtml(
          text
        )}</pre>`;
      } else {
        const dlUrl = URL.createObjectURL(outBlob);
        content.innerHTML = `
          <p style="color:#ffd;">Preview not supported for this file type.</p>
          <a class="btn-download-now" href="${dlUrl}" download="${meta.filename_original}">Download decrypted file</a>
        `;
      }
    } catch (decryptErr) {
      console.error("Decrypt error:", decryptErr);
      content.innerHTML = `<p style="color:red;">❌ Wrong passphrase — try again.</p>`;
    }
  } catch (err) {
    console.error("Preview flow error:", err);
    modal.classList.add("show");
    content.innerHTML = `<p style="color:red;">Unexpected error loading preview.</p>`;
  }
});

// helper: escape text for safe display
function escapeHtml(s) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

//handle close (x) click for preview modal
document.querySelector(".close-preview")?.addEventListener("click", () => {
  document.getElementById("file-preview-modal").classList.remove("show");
});

// ===== DOWNLOAD button: ask option, decrypt if needed, then save =====
document.addEventListener("click", async (e) => {
  if (!e.target.classList.contains("btn-download")) return;

  const fileId = e.target.getAttribute("data-id");
  const token = localStorage.getItem("token");

  const modal = document.getElementById("download-option-modal");
  modal.classList.remove("hidden");
  modal.classList.add("show");

  // blink animation when open
  modal.classList.add("blink-twice");
  setTimeout(() => modal.classList.remove("blink-twice"), 2000);

  // modal close function
  const closeModal = () => {
    modal.classList.remove("show");
    setTimeout(() => modal.classList.add("hidden"), 300);
  };
  // handle ❌ close click with smooth slide+fade
  const closeBtn = document.querySelector(".close-download");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      modal.classList.add("fade-out");
      setTimeout(() => {
        modal.classList.remove("show", "fade-out");
        modal.classList.add("hidden");
      }, 400);
    });
  }

  // === ENCRYPTED DOWNLOAD ===
  document.getElementById("download-encrypted").onclick = async () => {
    try {
      const res = await fetch(`http://localhost:5000/api/files/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Download failed");

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "encrypted_file";
      a.click();

      showDownloadPopup("Encrypted file downloaded securely 🔐", "success");
    } catch (err) {
      showDownloadPopup("Failed to download file ❌", "error");
    }
    closeModal();
  };

  // === DECRYPTED DOWNLOAD ===
  document.getElementById("download-decrypted").onclick = async () => {
    try {
      closeModal();
      const passphrase = await showDownloadPassphraseModal(); // ✅ apna modal yahan use kiya
      if (!passphrase) return closeModal();

      // fetch metadata
      const metaRes = await fetch(
        `http://localhost:5000/api/files/${fileId}/meta`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const meta = await metaRes.json();

      const salt = base64ToBuf(meta.salt);
      const key = await deriveKeyFromPassphrase(passphrase, salt);
      const fileRes = await fetch(`http://localhost:5000/api/files/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const encBuf = await fileRes.arrayBuffer();
      const iv = base64ToBuf(meta.iv);

      const plainBuf = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encBuf
      );

      const blob = new Blob([plainBuf], { type: meta.mime_type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = meta.filename_original;
      a.click();

      showDownloadPopup("Decrypted file downloaded safely ✅", "success");
    } catch (err) {
      console.error(err);
      showDownloadPopup("Wrong passphrase or decryption error ❌", "error");
    }
    closeModal();
  };
});

// ===== Floating Notification (smooth top drop + heartbeat blink) =====
function showDownloadPopup(message, type) {
  const popup = document.createElement("div");
  popup.className = `floating-popup ${type}`;
  popup.textContent = message;
  document.body.appendChild(popup);

  setTimeout(() => popup.classList.add("show"), 50); // slide down
  setTimeout(() => popup.classList.add("blink"), 400); // heartbeat blink
  setTimeout(() => {
    popup.classList.remove("show");
    setTimeout(() => popup.remove(), 500);
  }, 4000);
}

// ===== Custom Download Passphrase Modal =====
async function showDownloadPassphraseModal() {
  return new Promise((resolve) => {
    const modal = document.getElementById("download-passphrase-modal");
    const input = document.getElementById("download-pass-input");
    const okBtn = document.getElementById("download-pass-ok");
    const cancelBtn = document.getElementById("download-pass-cancel");
    const card = modal.querySelector(".modal-card");

    modal.classList.add("show");
    input.value = "";
    input.focus();

    const closeModal = () => modal.classList.remove("show");

    cancelBtn.onclick = () => {
      closeModal();
      resolve(null);
    };

    okBtn.onclick = () => {
      const val = input.value.trim();
      if (!val) {
        card.classList.add("error");
        setTimeout(() => card.classList.remove("error"), 500);
        return;
      }
      card.classList.add("success");
      setTimeout(() => {
        closeModal();
        resolve(val);
      }, 700);
    };
  });
}
// ====== PASSWORD VAULT FULL FEATURE ======
// — show list
async function loadVault() {
  try {
    const token = localStorage.getItem("token");
    const res = await fetch("http://localhost:5000/api/passwords", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    const container = document.getElementById("vault-list");
    container.innerHTML = "";
    if (data.items && data.items.length) {
      data.items.forEach((it) => {
        const el = document.createElement("div");
        el.className = "vault-item";
        el.innerHTML = `
          <div class="v-left">
            <strong>${escapeHtml(it.title)}</strong>
            <div class="muted">${escapeHtml(it.login || "")}</div>
          </div>
          <div class="v-actions">
            <button class="btn-view-secret" data-id="${it.id}">View</button>
            <button class="btn-edit-secret" data-id="${it.id}">Edit</button>
            <button class="btn-delete-secret" data-id="${it.id}">Delete</button>
          </div>
        `;
        container.appendChild(el);
      });
    } else {
      container.innerHTML = "<p class='muted'>No secrets saved yet.</p>";
    }
  } catch (err) {
    console.error("Vault load err", err);
  }
}

// ====== OPEN ADD MODAL ======
document.getElementById("vault-add-btn").addEventListener("click", () => {
  const modal = document.getElementById("vault-add-modal");
  modal.classList.remove("hidden");
  setTimeout(() => modal.classList.add("show"), 50);
});

// ====== CLOSE ADD MODAL ======
document.querySelector(".close-vault").addEventListener("click", () => {
  const modal = document.getElementById("vault-add-modal");
  modal.classList.remove("show");
  setTimeout(() => modal.classList.add("hidden"), 300);
});

document.getElementById("vault-cancel").addEventListener("click", () => {
  document.querySelector(".close-vault").click();
});

// ====== SAVE ENTRY (encrypt + POST) ======
document.getElementById("vault-save").addEventListener("click", async () => {
  const title = document.getElementById("vault-title").value.trim();
  const login = document.getElementById("vault-login").value.trim();
  const passwd = document.getElementById("vault-password").value;
  const notes = document.getElementById("vault-notes").value;

  if (!title || !passwd) {
    alert("Title and password required");
    return;
  }

  const passphrase = await showPassphraseModalAsync({
    placeholder: "Master passphrase to encrypt this entry",
    okText: "Encrypt & Save",
    cancelText: "Cancel",
  });
  if (!passphrase) return;

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassphrase(passphrase, salt);

  const plaintext = JSON.stringify({ password: passwd, login, notes });
  const encBuf = await encryptArrayBuffer(
    key,
    iv,
    new TextEncoder().encode(plaintext)
  );
  const encBase64 = bufToBase64(encBuf);
  const saltB64 = bufToBase64(salt);
  const ivB64 = bufToBase64(iv);

  const token = localStorage.getItem("token");
  const res = await fetch("http://localhost:5000/api/passwords", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      title,
      login,
      notes,
      encrypted_blob: encBase64,
      salt: saltB64,
      iv: ivB64,
    }),
  });

  const data = await res.json();
  if (res.ok) {
    showDownloadPopup("Saved to vault ✅", "success");
    document.querySelector(".close-vault").click();
    loadVault();
  } else {
    showDownloadPopup(data.msg || "Save failed ❌", "error");
  }
});

// ====== VIEW / DECRYPT ENTRY ======
document.addEventListener("click", async (e) => {
  if (!e.target.classList.contains("btn-view-secret")) return;
  const id = e.target.getAttribute("data-id");
  const token = localStorage.getItem("token");

  const metaRes = await fetch(
    `http://localhost:5000/api/passwords/${id}/meta`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  if (!metaRes.ok) {
    showDownloadPopup("Cannot fetch item", "error");
    return;
  }
  const meta = await metaRes.json();

  const passphrase = await showPassphraseModalAsync({
    placeholder: `Passphrase to decrypt "${meta.title}"`,
    okText: "Go",
    cancelText: "Cancel",
  });
  if (!passphrase) return;

  try {
    const saltBuf = base64ToBuf(meta.salt);
    const key = await deriveKeyFromPassphrase(passphrase, saltBuf);
    const fileRes = await fetch(`http://localhost:5000/api/passwords/${id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const encBase64 = await fileRes.text();
    const encBuf = base64ToBuf(encBase64);
    const ivBuf = base64ToBuf(meta.iv);

    const plainBuf = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBuf },
      key,
      encBuf
    );
    const plainText = new TextDecoder().decode(plainBuf);
    const obj = JSON.parse(plainText);

    const modal = document.getElementById("file-preview-modal");
    const content = modal.querySelector(".file-preview-content");
    modal.classList.add("show");
    content.innerHTML = `
      <h4>${escapeHtml(meta.title)}</h4>
      <p><strong>Login:</strong> ${escapeHtml(obj.login || "")}</p>
      <p><strong>Password:</strong> <span class="revealed-pass">${escapeHtml(
        obj.password
      )}</span></p>
      <p><strong>Notes:</strong> ${escapeHtml(obj.notes || "")}</p>
      <div class="modal-actions">
        <button id="vault-copy" class="btn-outline">Copy</button>
        <button id="vault-download-decrypted" class="btn-primary">Download</button>
      </div>
      <span class="close-preview">❌</span>
    `;

    // Close preview
    content.querySelector(".close-preview").onclick = () => {
      modal.classList.remove("show");
      setTimeout(() => modal.classList.add("hidden"), 300);
    };

    document.getElementById("vault-copy").onclick = () => {
      navigator.clipboard.writeText(obj.password);
      showDownloadPopup("Password copied to clipboard ✅", "success");
    };

    document.getElementById("vault-download-decrypted").onclick = () => {
      const blob = new Blob([plainText], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${meta.title}.txt`;
      a.click();
      showDownloadPopup("Downloaded decrypted secret ✅", "success");
    };
  } catch (err) {
    console.error("Decrypt vault error", err);
    showDownloadPopup("Wrong passphrase or corrupted entry ❌", "error");
  }
});

// ====== DELETE ENTRY ======
document.addEventListener("click", async (e) => {
  if (!e.target.classList.contains("btn-delete-secret")) return;
  const id = e.target.getAttribute("data-id");

  // Custom delete confirmation modal
  const modal = document.getElementById("delete-confirm-modal");
  modal.classList.remove("hidden");
  setTimeout(() => modal.classList.add("show"), 20);

  // ✅ Wait for user choice (confirm or cancel)
  const confirmed = await new Promise((resolve) => {
    const cancelBtn = document.getElementById("delete-cancel");
    const confirmBtn = document.getElementById("delete-confirm");

    cancelBtn.onclick = () => {
      modal.classList.remove("show");
      setTimeout(() => modal.classList.add("hidden"), 300);
      resolve(false);
    };

    confirmBtn.onclick = () => {
      modal.classList.remove("show");
      setTimeout(() => modal.classList.add("hidden"), 300);
      resolve(true);
    };
  });

  if (!confirmed) return; // user pressed Cancel ❌

  // ✅ Proceed with delete
  const token = localStorage.getItem("token");
  const res = await fetch(`http://localhost:5000/api/passwords/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });

  if (res.ok) {
    showDownloadPopup("Deleted ✅", "success");
    loadVault();
  } else {
    showDownloadPopup("Delete failed ❌", "error");
  }
});
// ====== EDIT ENTRY (open modal + prefill) ======
document.addEventListener("click", async (e) => {
  if (!e.target.classList.contains("btn-edit-secret")) return;
  const id = e.target.getAttribute("data-id");
  const token = localStorage.getItem("token");

  try {
    // meta fetch (title/login/notes) for prefill
    const metaRes = await fetch(
      `http://localhost:5000/api/passwords/${id}/meta`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    if (!metaRes.ok) {
      showDownloadPopup("Cannot fetch item for edit ❌", "error");
      return;
    }
    const meta = await metaRes.json();

    // pass the meta to modal
    meta.id = id; // ensure id exists for PUT
    showEditSecretModal(meta);
  } catch (err) {
    console.error("Edit fetch error:", err);
    showDownloadPopup("Server error while fetching secret ❌", "error");
  }
});

// ====== INIT ======
document.addEventListener("DOMContentLoaded", () => {
  loadFiles();
  loadVault();
});

// ====== PASSPHRASE MODAL ======
async function showPassphraseModalAsync({
  placeholder = "Enter passphrase",
  okText = "OK",
  cancelText = "Cancel",
} = {}) {
  return new Promise((resolve) => {
    let existing = document.getElementById("passphrase-modal");
    if (existing) existing.remove();

    const modal = document.createElement("div");
    modal.id = "passphrase-modal";
    modal.className = "modal show fade-in";
    modal.innerHTML = `
      <div class="modal-card slide-down">
        <h4>🔐 Enter Passphrase</h4>
        <input id="passphrase-input" type="password" placeholder="${placeholder}" />
        <div class="modal-actions">
          <button id="passphrase-cancel" class="btn-outline">${cancelText}</button>
          <button id="passphrase-ok" class="btn-primary">${okText}</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    modal.querySelector("#passphrase-cancel").onclick = () => {
      modal.classList.remove("show");
      setTimeout(() => modal.remove(), 300);
      resolve(null);
    };
    modal.querySelector("#passphrase-ok").onclick = () => {
      const val = document.getElementById("passphrase-input").value.trim();
      if (!val) {
        alert("Please enter a passphrase");
        return;
      }
      modal.classList.remove("show");
      setTimeout(() => modal.remove(), 300);
      resolve(val);
    };
  });
}
//edit btn event listner means edit btn ka code
// ✅ FINAL FIXED VERSION — edit modal
function showEditSecretModal(secret) {
  let modal = document.getElementById("edit-secret-modal");

  // agar pehli baar modal bana rahe ho
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "edit-secret-modal";
    modal.className = "modal hidden";
    modal.innerHTML = `
      <div class="modal-card slide-down" style="position: relative;">
        <span class="close-edit">❌</span>
        <h4>Edit Secret</h4>
        <input id="edit-secret-title" placeholder="Name" />
        <input id="edit-secret-login" placeholder="Login (optional)" />
        <textarea id="edit-secret-notes" placeholder="Notes (optional)"></textarea>
        <div class="modal-actions">
          <button id="save-edit" class="btn-primary">Save Changes</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    // close btn
    modal.querySelector(".close-edit").onclick = () => {
      modal.classList.remove("show");
      setTimeout(() => modal.classList.add("hidden"), 300);
    };
  }

  // 🔥 ensure elements exist before accessing
  const titleInput = modal.querySelector("#edit-secret-name");
  const loginInput = { value: "" };
  const notesInput = modal.querySelector("#edit-secret-value");

  if (!titleInput || !loginInput || !notesInput) {
    console.error("Edit modal elements missing");
    return;
  }

  // populate safely
  titleInput.value = secret.title || "";
  notesInput.value = secret.notes || "";

  // show animation
  modal.classList.remove("hidden");
  setTimeout(() => modal.classList.add("show"), 30);

  // save button handler
  const saveBtn = modal.querySelector("#save-edit");
  saveBtn.onclick = async () => {
    const newTitle = titleInput.value.trim();
    const newLogin = loginInput.value.trim();
    const newNotes = notesInput.value.trim();

    if (!newTitle) {
      alert("Title required");
      return;
    }

    const token = localStorage.getItem("token");
    try {
      const res = await fetch(
        `http://localhost:5000/api/passwords/${secret.id}`,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            title: newTitle,
            login: newLogin,
            notes: newNotes,
          }),
        }
      );

      if (res.ok) {
        showDownloadPopup("✅ Secret updated successfully", "success");
        modal.classList.remove("show");
        setTimeout(() => modal.classList.add("hidden"), 300);
        loadVault();
      } else {
        const err = await res.json().catch(() => ({}));
        showDownloadPopup(err.msg || "Update failed ❌", "error");
      }
    } catch (err) {
      console.error("Edit update error:", err);
      showDownloadPopup("Server error ❌", "error");
    }
  };
}

//desktop sidebar
const sidebar = document.getElementById("vault-sidebar");
const toggle = document.getElementById("vault-toggle");

// --- Desktop Click Toggle ---
toggle.addEventListener("click", () => {
  sidebar.classList.toggle("open");
});

// --- Mobile Swipe Control ---
let touchStartX = 0;
let touchEndX = 0;

document.addEventListener("touchstart", (e) => {
  touchStartX = e.changedTouches[0].screenX;
});

document.addEventListener("touchend", (e) => {
  touchEndX = e.changedTouches[0].screenX;
  handleGesture();
});

function handleGesture() {
  const diff = touchEndX - touchStartX;
  if (diff > 70) {
    // Swipe right → open
    sidebar.classList.add("open");
  } else if (diff < -70) {
    // Swipe left → close
    sidebar.classList.remove("open");
  }
}
