const translationsElement = document.getElementById("domini-i18n");
const translations = translationsElement ? JSON.parse(translationsElement.textContent) : {};

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
        method: "POST",
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
            headers: { "Accept": "application/json" },
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
