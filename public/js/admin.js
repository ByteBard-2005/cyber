async function loadBlacklist() {
  try {
    const res = await fetch("/api/blacklist");
    const data = await res.json();

    const tbody = document.getElementById("blacklist-body");

    if (!data.items || !data.items.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="2" class="empty-state">No domains in blacklist.</td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = data.items.map(item => `
      <tr>
        <td>${escapeHtml(item.domain || "-")}</td>
        <td>${escapeHtml(item.added_at || "-")}</td>
      </tr>
    `).join("");
  } catch (error) {
    console.error("Blacklist load error:", error);
  }
}

async function addBlacklistDomain() {
  const input = document.getElementById("domain-input");
  const message = document.getElementById("admin-message");
  const domain = input.value.trim().toLowerCase();

  message.textContent = "";
  message.className = "form-message";

  if (!domain) {
    message.textContent = "Please enter a domain.";
    message.classList.add("error-message");
    return;
  }

  try {
    const res = await fetch("/api/blacklist", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ domain })
    });

    const data = await res.json();

    if (res.ok) {
      message.textContent = "Domain added to blacklist.";
      message.classList.add("success-message");
      input.value = "";
      loadBlacklist();
    } else {
      message.textContent = data.error || "Could not add domain.";
      message.classList.add("error-message");
    }
  } catch (error) {
    message.textContent = "Server error. Please try again.";
    message.classList.add("error-message");
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", loadBlacklist);