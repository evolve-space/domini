const translationsElement = document.getElementById("domini-i18n");
const translations = translationsElement ? JSON.parse(translationsElement.textContent) : {};

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content ?? "";

function interpolate(text, element) {
    return text.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key) => {
        const value = element.dataset[`i18n${key.charAt(0).toUpperCase()}${key.slice(1)}`];
        return value || "";
    });
}

function applyLanguage(lang) {
    const dictionary = translations[lang];
    if (!dictionary) {
        return;
    }

    document.documentElement.lang = lang;

    document.querySelectorAll("[data-i18n]").forEach((element) => {
        const key = element.dataset.i18n;
        if (dictionary[key]) {
            element.textContent = interpolate(dictionary[key], element);
        }
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
        const key = element.dataset.i18nPlaceholder;
        if (dictionary[key]) {
            element.placeholder = dictionary[key];
        }
    });

    document.querySelectorAll("[data-i18n-title]").forEach((element) => {
        const key = element.dataset.i18nTitle;
        if (dictionary[key]) {
            element.title = dictionary[key];
        }
    });

    document.querySelectorAll(".lang-option").forEach((button) => {
        button.classList.toggle("is-active", button.dataset.lang === lang);
    });
}

async function persistLanguage(lang) {
    const response = await fetch(`/i18n/${lang}`, {
        headers: {
            "Accept": "application/json",
        },
    });

    if (!response.ok) {
        throw new Error(`Unable to persist language: ${lang}`);
    }
}

document.querySelectorAll(".lang-option").forEach((button) => {
    button.addEventListener("click", async () => {
        const lang = button.dataset.lang;
        applyLanguage(lang);

        try {
            await persistLanguage(lang);
        } catch (error) {
            console.error(error);
        }
    });
});

function statusLabel(status) {
    const lang = document.documentElement.lang || "es";
    const dictionary = translations[lang] || {};
    return dictionary[status] || status;
}

function setScanStatus(data) {
    const panel = document.getElementById("scan-status-panel");
    const text = document.getElementById("scan-status-text");
    const phase = document.getElementById("scan-phase");
    if (!panel || !text || !phase) {
        return;
    }
    panel.hidden = false;
    text.textContent = statusLabel(data.status || "running");
    phase.textContent = data.phase ? `${statusLabel("phase")}: ${data.phase}` : "";
}

async function pollScan(scanId) {
    const response = await fetch(`/scans/${scanId}/status`, { headers: { "Accept": "application/json" } });
    if (!response.ok) {
        return;
    }
    const data = await response.json();
    setScanStatus(data);
    if (data.status === "completed") {
        window.location.href = data.detail_url;
        return;
    }
    if (data.status !== "failed") {
        window.setTimeout(() => pollScan(scanId), 1800);
    }
}

const scanForm = document.getElementById("scan-form");
if (scanForm) {
    scanForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const input = document.getElementById("scan-target");
        const target = input ? input.value.trim() : "";
        if (!target) {
            return;
        }
        setScanStatus({ status: "queued", phase: "" });
        const response = await fetch("/scans", {
            method: "POST",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken,
            },
            body: JSON.stringify({ target }),
        });
        if (!response.ok) {
            setScanStatus({ status: "failed", phase: "" });
            return;
        }
        const data = await response.json();
        setScanStatus(data);
        pollScan(data.id);
    });
}

document.querySelectorAll(".clickable-row").forEach((row) => {
    row.addEventListener("click", (event) => {
        if (event.target.closest("a")) {
            return;
        }
        window.location.href = row.dataset.href;
    });
});

const rescanButton = document.getElementById("rescan-button");
if (rescanButton) {
    rescanButton.addEventListener("click", async () => {
        const response = await fetch(`/targets/${rescanButton.dataset.targetId}/rescan`, {
            method: "POST",
            headers: { "Accept": "application/json", "X-CSRF-Token": csrfToken },
        });
        if (!response.ok) {
            return;
        }
        const data = await response.json();
        window.location.href = `/dashboard?scan_id=${data.id}`;
    });
}

const params = new URLSearchParams(window.location.search);
const activeScanId = params.get("scan_id");
if (activeScanId) {
    pollScan(activeScanId);
}

document.documentElement.dataset.ready = "true";

// Password strength validator — login (register mode) and reset_password
(function () {
    const input = document.getElementById("password-input");
    const hint = document.getElementById("password-hint");
    if (!input || !hint) return;
    input.addEventListener("input", () => {
        const valid = input.value.length >= 12 && /[A-Za-z]/.test(input.value) && /\d/.test(input.value) && /[^A-Za-z0-9]/.test(input.value);
        hint.classList.toggle("is-valid", valid);
    });
}());

// Dashboard: delete modal (table with multiple targets)
// Discriminator: only dashboard has #delete-target-name span
(function () {
    const modal = document.getElementById("delete-modal");
    const modalName = document.getElementById("delete-target-name");
    if (!modal || !modalName) return;
    let pendingId = null;
    let pendingRow = null;
    document.querySelectorAll(".delete-target-btn").forEach(function (btn) {
        btn.addEventListener("click", function (e) {
            e.stopPropagation();
            pendingId = btn.dataset.targetId;
            pendingRow = btn.closest("tr");
            modalName.textContent = btn.dataset.targetName;
            modal.showModal();
        });
    });
    modal.addEventListener("close", async function () {
        if (modal.returnValue !== "confirm" || !pendingId) return;
        try {
            const resp = await fetch("/targets/" + pendingId, { method: "DELETE", headers: { "X-CSRF-Token": csrfToken } });
            if (resp.ok && pendingRow) pendingRow.remove();
        } catch (err) {
            console.error(err);
        } finally {
            pendingId = null;
            pendingRow = null;
        }
    });
}());

// Target detail: delete modal (single target)
// Discriminator: only target_detail has #delete-target-btn
(function () {
    const btn = document.getElementById("delete-target-btn");
    const modal = document.getElementById("delete-modal");
    if (!btn || !modal) return;
    btn.addEventListener("click", function () { modal.showModal(); });
    modal.addEventListener("close", async function () {
        if (modal.returnValue !== "confirm") return;
        try {
            const resp = await fetch("/targets/" + btn.dataset.targetId, { method: "DELETE", headers: { "X-CSRF-Token": csrfToken } });
            if (resp.ok) window.location.href = "/dashboard";
        } catch (err) {
            console.error(err);
        }
    });
}());

// Score ring: apply CSS custom property from data attribute
(function () {
    const ring = document.querySelector(".score-ring[data-score-offset]");
    if (ring) ring.style.setProperty("--score-offset", ring.dataset.scoreOffset);
}());

// Chart.js risk evolution chart
(function () {
    const canvas = document.getElementById("risk-chart");
    if (!canvas || !window.Chart) return;
    const chartData = JSON.parse(canvas.dataset.chart || '{"labels":[],"scores":[]}');
    const ctx = canvas.getContext("2d");
    const gradient = ctx.createLinearGradient(0, 0, canvas.clientWidth || 600, 0);
    gradient.addColorStop(0, "#0066ff");
    gradient.addColorStop(1, "#00d4ff");
    new Chart(ctx, {
        type: "line",
        data: {
            labels: chartData.labels,
            datasets: [{
                data: chartData.scores,
                borderColor: gradient,
                backgroundColor: "rgba(0, 212, 255, 0.12)",
                pointBackgroundColor: "#00d4ff",
                pointBorderColor: "#edf4ff",
                pointRadius: 4,
                tension: 0.32,
                fill: true,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#8b98a9" }, grid: { color: "rgba(148, 163, 184, 0.12)" } },
                y: { min: 0, max: 100, ticks: { color: "#8b98a9" }, grid: { color: "rgba(148, 163, 184, 0.12)" } },
            },
        },
    });
}());
