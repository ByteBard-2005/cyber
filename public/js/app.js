async function analyzeURL() {
  const input = document.getElementById("url-input");
  const btn = document.getElementById("analyze-btn");
  const btnText = document.getElementById("btn-text");
  const btnSpinner = document.getElementById("btn-spinner");
  const resultArea = document.getElementById("result-area");

  const url = input.value.trim();

  if (!url) {
    input.focus();
    return;
  }

  btn.disabled = true;
  btnText.textContent = "Analyzing...";
  btnSpinner.classList.remove("hidden");
  resultArea.classList.add("hidden");
  resultArea.innerHTML = "";

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const contentType = res.headers.get("content-type") || "";
    let data;

    if (contentType.includes("application/json")) {
      data = await res.json();
    } else {
      const text = await res.text();

      if (res.status === 401 || text.includes("<!DOCTYPE html")) {
        throw new Error("You are not logged in or the server returned an HTML page instead of JSON.");
      }

      throw new Error("Server returned unexpected response.");
    }

    if (!res.ok) {
      throw new Error(data.error || "Server error");
    }

    renderResult(data, resultArea);

    if (typeof loadDashboardData === "function") {
      loadDashboardData();
    }

    if (typeof loadHistory === "function") {
      loadHistory();
    }
  } catch (err) {
    resultArea.innerHTML = `
      <div class="error-box">
        <strong>Error:</strong> ${err.message}
      </div>
    `;
  } finally {
    btn.disabled = false;
    btnText.textContent = "Analyze";
    btnSpinner.classList.add("hidden");
    resultArea.classList.remove("hidden");
  }
}

function renderResult(data, container) {
  const { verdict, risk_score, url, layers } = data;
  const scorePercent = Math.round((risk_score || 0) * 100);
  const verdictLabel = verdict.charAt(0).toUpperCase() + verdict.slice(1);

  const allFlags = data.flags || [
    ...(layers?.url_analysis?.flags || []),
    ...(layers?.content_analysis?.flags || []),
    ...(layers?.threat_feeds?.flags || [])
  ];

  const flagsHTML = allFlags.length
    ? `
      <div class="flags-section">
        <h4>Detected signals</h4>
        <div class="flags-list">
          ${allFlags.map(flag => `<span class="flag-tag">${escapeHtml(flag.replace(/_/g, " "))}</span>`).join("")}
        </div>
      </div>
    `
    : `
      <div class="flags-section">
        <h4>Detected signals</h4>
        <div class="flags-list">
          <span class="flag-tag">No major suspicious signals</span>
        </div>
      </div>
    `;

  const layerScores = [
    { label: "URL analysis", score: layers?.url_analysis?.score ?? "—" },
    { label: "Content analysis", score: layers?.content_analysis?.score ?? "—" },
    { label: "Threat feeds", score: layers?.threat_feeds?.score ?? "—" }
  ];

  const layerScoresHTML = layerScores.map(layer => `
    <div class="layer-score-row">
      <span>${layer.label}</span>
      <span class="layer-score-val">
        ${typeof layer.score === "number" ? `${Math.round(layer.score * 100)}%` : layer.score}
      </span>
    </div>
  `).join("");

  container.innerHTML = `
    <div class="result-box ${verdict}">
      <div class="verdict-row">
        <span class="verdict-badge ${verdict}">${verdictLabel}</span>
        <span class="risk-score">Risk score: <span>${scorePercent}%</span></span>
      </div>

      <div class="score-bar-wrap">
        <div class="score-bar ${verdict}" style="width: ${scorePercent}%"></div>
      </div>

      <div class="layers-breakdown">
        <h4>Analyzed URL</h4>
        <div class="layer-score-row">
          <span>URL</span>
          <span class="layer-score-val">${escapeHtml(url)}</span>
        </div>
      </div>

      ${flagsHTML}

      <div class="layers-breakdown">
        <h4>Layer scores</h4>
        ${layerScoresHTML}
      </div>
    </div>
  `;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("url-input");
  if (input) {
    input.addEventListener("keydown", e => {
      if (e.key === "Enter") analyzeURL();
    });
  }
});