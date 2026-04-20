async function loadHistory() {
  try {
    const search = document.getElementById("search-input").value.trim().toLowerCase();
    const verdict = document.getElementById("verdict-filter").value;
    const sort = document.getElementById("sort-filter").value;

    const res = await fetch("/api/history");
    const data = await res.json();

    let items = data.history || [];

    if (search) {
      items = items.filter(item =>
        (item.target || "").toLowerCase().includes(search) ||
        (item.flags || "").toLowerCase().includes(search) ||
        (item.type || "").toLowerCase().includes(search)
      );
    }

    if (verdict !== "all") {
      items = items.filter(item => (item.verdict || "").toLowerCase() === verdict);
    }

    if (sort === "highest_risk") {
      items.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
    } else if (sort === "lowest_risk") {
      items.sort((a, b) => (a.risk_score || 0) - (b.risk_score || 0));
    } else {
      items.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    }

    renderHistory(items);
  } catch (error) {
    console.error("History load error:", error);
  }
}

function renderHistory(items) {
  const tbody = document.getElementById("history-body");

  if (!items.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state">No matching scan history found.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = items.map(item => {
    const flagsArray = item.flags
      ? item.flags.split(",").map(x => x.trim()).filter(Boolean)
      : [];

    const flagsHtml = flagsArray.length
      ? flagsArray.slice(0, 8).map(flag => `
          <span class="small-flag">${escapeHtml(flag.replace(/_/g, " "))}</span>
        `).join("")
      : `<span class="small-flag">No major flags</span>`;

    return `
      <tr>
        <td>${escapeHtml(item.created_at || "-")}</td>
        <td>${escapeHtml(item.type || "-")}</td>
        <td class="table-url">${escapeHtml(item.target || "-")}</td>
        <td>
          <span class="verdict-pill ${item.verdict}">
            ${escapeHtml(item.verdict || "-")}
          </span>
        </td>
        <td>${Math.round((item.risk_score || 0) * 100)}%</td>
        <td><div class="table-flags">${flagsHtml}</div></td>
      </tr>
    `;
  }).join("");
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", () => {
  loadHistory();

  const applyBtn = document.getElementById("apply-filters-btn");
  if (applyBtn) applyBtn.addEventListener("click", loadHistory);

  const searchInput = document.getElementById("search-input");
  if (searchInput) {
    searchInput.addEventListener("keydown", e => {
      if (e.key === "Enter") loadHistory();
    });
  }

  const verdictFilter = document.getElementById("verdict-filter");
  const sortFilter = document.getElementById("sort-filter");

  if (verdictFilter) verdictFilter.addEventListener("change", loadHistory);
  if (sortFilter) sortFilter.addEventListener("change", loadHistory);
});