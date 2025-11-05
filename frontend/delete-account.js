// delete-account.final.js
// Final client-side delete-account handler
// Drop this file in your frontend and make sure your delete page includes it.

(() => {
  const startBtn = document.getElementById("start-delete");
  const cancelBtn = document.getElementById("cancel-delete");
  const modal = document.getElementById("confirm-delete-modal");
  const confirmGo = document.getElementById("confirm-go");
  const confirmCancel = document.getElementById("confirm-cancel");
  const REDIRECT_TO = "/"; // <-- change to "/login.html" or "/index.html" if you want

  function showToast(message, type = "info", duration = 3500) {
    if (typeof showDownloadPopup === "function") {
      showDownloadPopup(message, type === "error" ? "error" : "success");
      return;
    }
    // fallback small toast
    let root = document.getElementById("toast-root");
    if (!root) {
      root = document.createElement("div");
      root.id = "toast-root";
      root.style.position = "fixed";
      root.style.right = "16px";
      root.style.top = "16px";
      root.style.zIndex = 99999;
      document.body.appendChild(root);
    }
    const el = document.createElement("div");
    el.style.cssText =
      "background:#0b1220;color:#fff;padding:10px 14px;border-radius:10px;margin-top:8px;box-shadow:0 6px 20px rgba(0,0,0,0.6);";
    el.innerText = message;
    root.appendChild(el);
    setTimeout(() => el.remove(), duration);
  }

  // open confirmation modal (start)
  startBtn?.addEventListener("click", () => {
    const email = document.getElementById("delete-email").value.trim();
    const pw = document.getElementById("delete-password").value.trim();
    if (!email || !pw) {
      showToast("Please enter email and password to proceed.", "error");
      return;
    }
    if (!modal) return showToast("Confirm modal missing.", "error");
    modal.classList.remove("hidden");
    setTimeout(() => modal.classList.add("show"), 20);
    document.getElementById("confirm-word").value = "";
  });

  // cancel flows
  cancelBtn?.addEventListener("click", () => {
    window.history.back();
  });
  confirmCancel?.addEventListener("click", () => {
    if (!modal) return;
    modal.classList.remove("show");
    setTimeout(() => modal.classList.add("hidden"), 250);
  });

  // helper: cleanup client state (token, caches, service workers)
  async function clientCleanup() {
    try {
      localStorage.removeItem("token");
      sessionStorage.clear();

      // unregister all service workers (best-effort)
      if ("serviceWorker" in navigator) {
        try {
          const regs = await navigator.serviceWorker.getRegistrations();
          await Promise.all(regs.map((r) => r.unregister()));
        } catch (e) {
          console.warn("SW cleanup failed", e);
        }
      }

      // clear caches (best-effort)
      if (window.caches && caches.keys) {
        try {
          const keys = await caches.keys();
          await Promise.all(keys.map((k) => caches.delete(k)));
        } catch (e) {
          console.warn("Cache cleanup failed", e);
        }
      }

      // push a new history state and then replace to REDIRECT_TO so Back won't restore current session page
      try {
        history.pushState(null, "", location.href);
        history.replaceState(null, "", REDIRECT_TO);
      } catch (e) {
        // ignore
      }
    } catch (err) {
      console.warn("client cleanup error", err);
    }
  }

  // final confirmation and API request
  confirmGo?.addEventListener("click", async () => {
    const confirmWord = document.getElementById("confirm-word").value.trim();
    if (confirmWord !== "DELETE") {
      showToast('Type "DELETE" to confirm.', "error");
      return;
    }

    const reason = document.getElementById("delete-reason")?.value || "";
    const email = document.getElementById("delete-email").value.trim();
    const password = document.getElementById("delete-password").value.trim();
    const token = localStorage.getItem("token") || "";

    // UI lock
    confirmGo.disabled = true;
    confirmGo.innerText = "Deleting...";

    try {
      const res = await fetch("http://localhost:5000/api/delete-account", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ email, password, reason }),
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        // cleanup everything client-side first
        await clientCleanup();

        showToast("Account deleted — redirecting...", "success");

        // small delay for UX, then hard redirect and replace history
        setTimeout(() => {
          // hard replace so user can't go back
          window.location.replace(REDIRECT_TO);
        }, 900);

        return;
      } else {
        // show server message (if any)
        showToast(data.msg || data.message || "Delete failed", "error");
        confirmGo.disabled = false;
        confirmGo.innerText = "Yes, delete account";
        // close modal
        modal?.classList.remove("show");
        setTimeout(() => modal?.classList.add("hidden"), 250);
      }
    } catch (err) {
      console.error("Delete request error", err);
      showToast("Server error — try again", "error");
      confirmGo.disabled = false;
      confirmGo.innerText = "Yes, delete account";
      modal?.classList.remove("show");
      setTimeout(() => modal?.classList.add("hidden"), 250);
    }
  });
})();
