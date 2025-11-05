const shareLink = window.location.origin + "/index.html";  
const shareText =
  "🚀 Experience secure cloud storage like never before! Store your secrets safely with 100% encryption. Try it now 👇";

document.querySelector(".whatsapp").onclick = () => {
  window.open(
    `https://wa.me/?text=${encodeURIComponent(shareText + " " + shareLink)}`,
    "_blank"
  );
};

document.querySelector(".facebook").onclick = () => {
  window.open(
    `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(
      shareLink
    )}`,
    "_blank"
  );
};

document.querySelector(".instagram").onclick = () => {
  showPopup("Instagram doesn’t allow direct link sharing. Copy link instead!");
};

document.querySelector(".bluetooth").onclick = () => {
  showPopup(
    "Bluetooth sharing works only via your device’s native share menu."
  );
};

document.querySelector(".copy").onclick = async () => {
  try {
    await navigator.clipboard.writeText(shareLink);
    showPopup("Link copied to clipboard ✅");
  } catch {
    showPopup("Failed to copy link ❌");
  }
};

// Popup system
function showPopup(message) {
  const popup = document.getElementById("popup");
  const messageBox = document.getElementById("popup-message");
  messageBox.textContent = message;
  popup.classList.remove("hidden");
}

document.getElementById("popup-ok").onclick = () => {
  document.getElementById("popup").classList.add("hidden");
};
