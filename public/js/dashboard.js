let dashboardChart = null;

async function loadDashboard() {
  try {
    const res = await fetch("/api/dashboard");
    const data = await res.json();

    const cards = data.cards || {};
    const chart = data.chart || {};
    const recent = data.recent || [];

    document.getElementById("total-count").textContent = cards.total_scans || 0;
    document.getElementById("phishing-count").textContent = cards.phishing || 0;
    document.getElementById("suspicious-count").textContent = cards.suspicious || 0;
    document.getElementById("safe-count").textContent = cards.safe || 0;

    renderChart(chart);
    renderRecent(recent);
  } catch (error) {
    console.error("Dashboard load error:", error);
  }
}

function renderChart(chartData) {
  const canvas = document.getElementById("bar-chart");
  if (!canvas || typeof Chart === "undefined") return;

  const ctx = canvas.getContext("2d");

  if (dashboardChart) dashboardChart.destroy();

  dashboardChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: chartData.labels || [],
      datasets: [
        {
          label: "Safe",
          data: chartData.safe || [],
          backgroundColor: "rgba(22,163,74,0.6)",
          borderRadius: 4
        },
        {
          label: "Suspicious",
          data: chartData.suspicious || [],
          backgroundColor: "rgba(245,158,11,0.6)",
          borderRadius: 4
        },
        {
          label: "Phishing",
          data: chartData.phishing || [],
          backgroundColor: "rgba(220,38,38,0.6)",
          borderRadius: 4
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: "#6b7280",
            font: { size: 12 }
          }
        }
      },
      scales: {
        x: {
          stacked: true,
          ticks: { color: "#6b7280" },
          grid: { color: "rgba(0,0,0,0.05)" }
        },
        y: {
          stacked: true,
          beginAtZero: true,
          ticks: { color: "#6b7280" },
          grid: { color: "rgba(0,0,0,0.05)" }
        }
      }
    }
  });
}

function renderRecent(items) {
  const tbody = document.getElementById("recent-body");

  if (!items.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="empty-state">No scans yet.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = items.map(item => {
    const flagsArray = item.flags
      ? item.flags.split(",").map(x => x.trim()).filter(Boolean)
      : [];

    const flagsHtml = flagsArray.length
      ? flagsArray.slice(0, 5).map(flag => `
          <span class="small-flag">${escapeHtml(flag.replace(/_/g, " "))}</span>
        `).join("")
      : `<span class="small-flag">No major flags</span>`;

    return `
      <tr>
        <td>${escapeHtml(item.created_at || "-")}</td>
        <td>${escapeHtml(item.type || "-")}</td>
        <td class="table-url">${escapeHtml(item.target || "-")}</td>
        <td><span class="verdict-pill ${item.verdict}">${escapeHtml(item.verdict || "-")}</span></td>
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

document.addEventListener("DOMContentLoaded", loadDashboard);