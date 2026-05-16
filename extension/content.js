const API_URL = "http://localhost:8000/analyse";
const BANNER_ID = "gmail-ai-phishing-detector-banner";
const BANNER_POSITION_KEY = "gmail-ai-phishing-detector-banner-position";
const ANALYSIS_DELAY_MS = 750;
const RETRY_DELAY_MS = 5000;
const DEFAULT_BANNER_TOP = 72;
const DEFAULT_BANNER_MARGIN = 18;
const DRAG_CLICK_THRESHOLD = 5;

let lastAnalysedFingerprint = "";
let lastFailedFingerprint = "";
let lastFailedAt = 0;
let dismissedFingerprint = "";
let analysisTimer = null;
let currentRequestController = null;
let bannerPosition = loadBannerPosition();
let bannerDragState = null;
let suppressNextPillClick = false;

function isVisible(element) {
  if (!element) return false;

  const style = window.getComputedStyle(element);
  const rect = element.getBoundingClientRect();

  return (
    style.display !== "none" &&
    style.visibility !== "hidden" &&
    style.opacity !== "0" &&
    rect.width > 0 &&
    rect.height > 0
  );
}

function normaliseText(value) {
  return value.replace(/\s+/g, " ").trim();
}

function extractEmailFromValue(value) {
  if (!value) return null;
  const match = String(value).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0].toLowerCase() : null;
}

function getGmailMainView() {
  return document.querySelector('[role="main"]') || document.body;
}

function getVisibleMessageBodies() {
  const mainView = getGmailMainView();
  const selectors = [
    ".a3s.aiL",
    ".a3s",
    '[data-message-id] .a3s',
    '[role="listitem"] .a3s'
  ];

  return Array.from(mainView.querySelectorAll(selectors.join(",")))
    .filter(isVisible)
    .filter((body) => normaliseText(body.innerText || "").length > 0);
}

function getMessageContainer(body) {
  return (
    body.closest(".adn") ||
    body.closest("[data-message-id]") ||
    body.closest("[role='listitem']") ||
    getGmailMainView()
  );
}

function extractEmailFromElement(element) {
  const values = [
    element.getAttribute("email"),
    element.getAttribute("data-hovercard-id"),
    element.getAttribute("aria-label"),
    element.getAttribute("title"),
    element.textContent
  ];

  for (const value of values) {
    const email = extractEmailFromValue(value);
    if (email) return email;
  }

  return null;
}

function getSenderSearchAreas(messageBodies) {
  const areas = [];

  for (const body of messageBodies) {
    const container = getMessageContainer(body);
    if (!container || areas.includes(container)) continue;

    const headerSelectors = [
      ".gE",
      ".gH",
      ".iw",
      ".adn > .aju",
      ".adn > .gs",
      "[role='heading']"
    ];

    const headers = Array.from(container.querySelectorAll(headerSelectors.join(",")))
      .filter(isVisible);

    if (headers.length) {
      areas.push(...headers);
    } else {
      areas.push(container);
    }
  }

  return areas;
}

function extractSenderEmail(messageBodies) {
  const senderSelectors = [
    ".gD[email]",
    ".gD[data-hovercard-id*='@']",
    ".gD[title*='@']",
    ".go[email]",
    ".go[data-hovercard-id*='@']",
    "[email]",
    "[data-hovercard-id*='@']",
    "[aria-label*='@']",
    "[title*='@']"
  ];

  for (const area of getSenderSearchAreas(messageBodies)) {
    const candidates = Array.from(area.querySelectorAll(senderSelectors.join(",")))
      .filter((candidate) => isVisible(candidate) && !candidate.closest(".a3s"));

    for (const candidate of candidates) {
      const email = extractEmailFromElement(candidate);
      if (email) return email;
    }
  }

  return null;
}

function extractOpenedEmail() {
  const messageBodies = getVisibleMessageBodies();
  const emailText = messageBodies
    .map((body) => body.innerText || "")
    .join("\n\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  const links = new Set();

  for (const body of messageBodies) {
    const anchors = Array.from(body.querySelectorAll("a[href]")).filter(isVisible);

    for (const anchor of anchors) {
      const href = anchor.href;

      if (!href) continue;
      if (href.startsWith("mailto:")) continue;
      if (href.startsWith("tel:")) continue;
      if (href.startsWith("javascript:")) continue;

      links.add(href);
    }
  }

  return {
    email_text: emailText,
    links: Array.from(links),
    sender_email: extractSenderEmail(messageBodies) || null
  };
}

function buildFingerprint(payload) {
  return JSON.stringify({
    hash: window.location.hash,
    email_text: payload.email_text.slice(0, 8000),
    links: payload.links,
    sender_email: payload.sender_email
  });
}

function toDisplayLevel(level) {
  const normalised = String(level || "low").toLowerCase();

  if (normalised === "high") return "High";
  if (normalised === "medium") return "Medium";
  return "Low";
}

function riskClass(level) {
  const normalised = String(level || "low").toLowerCase();

  if (normalised === "high") return "gpd-risk-high";
  if (normalised === "medium") return "gpd-risk-medium";
  return "gpd-risk-low";
}

function getRiskScore(result) {
  const value = Number(result.risk_score ?? result.score ?? 0);
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function getReasons(result) {
  if (!Array.isArray(result.reasons)) return [];
  return result.reasons
    .map((reason) => String(reason).trim())
    .filter(Boolean);
}

function statusText(value) {
  if (value === true) return "Found";
  if (value === false) return "Missing";
  return "Inconclusive";
}

function loadBannerPosition() {
  try {
    const saved = window.localStorage.getItem(BANNER_POSITION_KEY);
    if (!saved) return null;

    const parsed = JSON.parse(saved);
    if (Number.isFinite(parsed.left) && Number.isFinite(parsed.top)) {
      return {
        left: parsed.left,
        top: parsed.top
      };
    }
  } catch (error) {
    console.warn("AI Phishing Risk Assistant: could not load banner position", error);
  }

  return null;
}

function saveBannerPosition(position) {
  try {
    window.localStorage.setItem(BANNER_POSITION_KEY, JSON.stringify(position));
  } catch (error) {
    console.warn("AI Phishing Risk Assistant: could not save banner position", error);
  }
}

function defaultBannerPosition(banner) {
  const rect = banner.getBoundingClientRect();
  return {
    left: window.innerWidth - rect.width - DEFAULT_BANNER_MARGIN,
    top: DEFAULT_BANNER_TOP
  };
}

function clampBannerPosition(position, banner) {
  const rect = banner.getBoundingClientRect();
  const width = rect.width || banner.offsetWidth || 160;
  const height = rect.height || banner.offsetHeight || 60;
  const minLeft = DEFAULT_BANNER_MARGIN;
  const minTop = DEFAULT_BANNER_MARGIN;
  const maxLeft = Math.max(minLeft, window.innerWidth - width - DEFAULT_BANNER_MARGIN);
  const maxTop = Math.max(minTop, window.innerHeight - height - DEFAULT_BANNER_MARGIN);

  return {
    left: Math.min(Math.max(position.left, minLeft), maxLeft),
    top: Math.min(Math.max(position.top, minTop), maxTop)
  };
}

function applyBannerPosition(banner, shouldSave = false) {
  const basePosition = bannerPosition || defaultBannerPosition(banner);
  bannerPosition = clampBannerPosition(basePosition, banner);
  banner.style.left = `${bannerPosition.left}px`;
  banner.style.top = `${bannerPosition.top}px`;
  banner.style.right = "auto";

  if (shouldSave) {
    saveBannerPosition(bannerPosition);
  }
}

function isDragBlockedTarget(target) {
  if (!(target instanceof Element)) {
    return false;
  }

  return Boolean(
    target.closest("button, a, input, textarea, select, [data-gpd-no-drag='true']")
  );
}

// Drag logic: pointer events keep both mouse and touch handling simple.
// The final clamped position is stored in localStorage so Gmail reloads keep it.
function startBannerDrag(event, banner) {
  if (event.button !== 0 || isDragBlockedTarget(event.target)) {
    return;
  }

  const rect = banner.getBoundingClientRect();
  bannerDragState = {
    pointerId: event.pointerId,
    startX: event.clientX,
    startY: event.clientY,
    startLeft: rect.left,
    startTop: rect.top,
    moved: false
  };

  banner.classList.add("gpd-dragging");
  banner.setPointerCapture?.(event.pointerId);
  event.preventDefault();
}

function handleBannerDrag(event, banner) {
  if (!bannerDragState || event.pointerId !== bannerDragState.pointerId) {
    return;
  }

  const deltaX = event.clientX - bannerDragState.startX;
  const deltaY = event.clientY - bannerDragState.startY;
  if (Math.abs(deltaX) > DRAG_CLICK_THRESHOLD || Math.abs(deltaY) > DRAG_CLICK_THRESHOLD) {
    bannerDragState.moved = true;
  }

  bannerPosition = clampBannerPosition(
    {
      left: bannerDragState.startLeft + deltaX,
      top: bannerDragState.startTop + deltaY
    },
    banner
  );

  banner.style.left = `${bannerPosition.left}px`;
  banner.style.top = `${bannerPosition.top}px`;
  banner.style.right = "auto";
}

function stopBannerDrag(event, banner) {
  if (!bannerDragState || event.pointerId !== bannerDragState.pointerId) {
    return;
  }

  if (bannerDragState.moved) {
    suppressNextPillClick = true;
    window.setTimeout(() => {
      suppressNextPillClick = false;
    }, 0);
  }

  banner.releasePointerCapture?.(event.pointerId);
  banner.classList.remove("gpd-dragging");
  saveBannerPosition(bannerPosition || clampBannerPosition(defaultBannerPosition(banner), banner));
  bannerDragState = null;
}

function enableBannerDrag(banner, handle) {
  handle.onpointerdown = (event) => startBannerDrag(event, banner);
  banner.onpointermove = (event) => handleBannerDrag(event, banner);
  banner.onpointerup = (event) => stopBannerDrag(event, banner);
  banner.onpointercancel = (event) => stopBannerDrag(event, banner);
}

function clearDirectBannerDrag(banner) {
  banner.onpointerdown = null;
}

function ensureBanner() {
  let banner = document.getElementById(BANNER_ID);

  if (!banner) {
    banner = document.createElement("section");
    banner.id = BANNER_ID;
    banner.setAttribute("aria-live", "polite");
    banner.setAttribute("role", "status");
    document.body.appendChild(banner);
  }

  return banner;
}

function renderBanner(result, fingerprint = "") {
  if (fingerprint && fingerprint === dismissedFingerprint) {
    return;
  }

  const banner = ensureBanner();
  renderFullBanner(banner, result, fingerprint);
}

function renderFullBanner(banner, result, fingerprint = "") {
  const level = toDisplayLevel(result.risk_level);
  const score = getRiskScore(result);
  const reasons = getReasons(result);
  const fallbackReason = "No obvious phishing indicators found by the local rule-based scan.";
  const allReasons = reasons.length ? reasons : [fallbackReason];
  let expanded = false;

  banner.className = `gpd-banner gpd-full ${riskClass(level)}`;
  banner.removeAttribute("tabindex");
  banner.removeAttribute("aria-label");
  banner.onclick = null;
  banner.onkeydown = null;
  clearDirectBannerDrag(banner);
  banner.innerHTML = "";

  const header = document.createElement("div");
  header.className = "gpd-banner-header";
  header.title = "Drag to move";

  const titleWrap = document.createElement("div");
  titleWrap.className = "gpd-banner-title-wrap";

  const label = document.createElement("span");
  label.className = "gpd-risk-label";
  label.textContent = level;

  const title = document.createElement("div");
  title.className = "gpd-banner-title";
  title.textContent = "AI Phishing Risk Assistant";

  titleWrap.append(label, title);

  const actions = document.createElement("div");
  actions.className = "gpd-banner-actions";

  const minimiseButton = document.createElement("button");
  minimiseButton.type = "button";
  minimiseButton.className = "gpd-banner-minimise";
  minimiseButton.setAttribute("aria-label", "Minimise phishing warning");
  minimiseButton.setAttribute("data-gpd-no-drag", "true");
  minimiseButton.textContent = "-";
  minimiseButton.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    // Minimise logic: keep the same banner node and position, but render only
    // the compact risk pill. The pill can be clicked later to restore details.
    renderMinimisedBanner(banner, result, fingerprint);
  });

  const closeButton = document.createElement("button");
  closeButton.type = "button";
  closeButton.className = "gpd-banner-close";
  closeButton.setAttribute("aria-label", "Close phishing warning");
  closeButton.setAttribute("data-gpd-no-drag", "true");
  closeButton.textContent = "x";
  closeButton.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (fingerprint) {
      dismissedFingerprint = fingerprint;
    }
    banner.remove();
  });

  actions.append(minimiseButton, closeButton);
  header.append(titleWrap, actions);
  enableBannerDrag(banner, header);

  const scoreText = document.createElement("div");
  scoreText.className = "gpd-banner-score";
  scoreText.textContent = `Risk score: ${score}/100`;

  const summaryText = document.createElement("div");
  summaryText.className = "gpd-banner-summary";
  summaryText.textContent = result.summary || "Review the warning signs before trusting this email.";

  const meta = document.createElement("dl");
  meta.className = "gpd-banner-meta";

  function addMeta(label, value, statusClass = "") {
    const term = document.createElement("dt");
    term.textContent = label;

    const description = document.createElement("dd");
    description.textContent = value;
    if (statusClass) {
      description.className = statusClass;
    }

    meta.append(term, description);
  }

  addMeta("Sender domain", result.sender_domain || "Unknown");
  addMeta("SPF", statusText(result.spf_found), `gpd-auth-${statusText(result.spf_found).toLowerCase()}`);
  addMeta("DMARC", statusText(result.dmarc_found), `gpd-auth-${statusText(result.dmarc_found).toLowerCase()}`);

  const bankingWarning = document.createElement("div");
  bankingWarning.className = "gpd-banking-warning";
  bankingWarning.textContent = "Possible banking impersonation detected";

  const reasonList = document.createElement("ul");
  reasonList.className = "gpd-banner-reasons";

  const viewDetailsButton = document.createElement("button");
  viewDetailsButton.type = "button";
  viewDetailsButton.className = "gpd-details-button";
  viewDetailsButton.setAttribute("data-gpd-no-drag", "true");

  function renderReasons() {
    reasonList.innerHTML = "";

    const visibleReasons = expanded ? allReasons : allReasons.slice(0, 3);
    for (const reason of visibleReasons) {
      const item = document.createElement("li");
      item.textContent = reason;
      reasonList.appendChild(item);
    }

    viewDetailsButton.textContent = expanded ? "Hide details" : "View details";
  }

  viewDetailsButton.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    expanded = !expanded;
    renderReasons();
  });

  renderReasons();
  banner.append(header, scoreText, summaryText, meta);

  if (result.banking_impersonation_detected) {
    banner.appendChild(bankingWarning);
  }

  banner.appendChild(reasonList);

  if (allReasons.length > 3) {
    banner.appendChild(viewDetailsButton);
  }

  applyBannerPosition(banner, false);
}

function renderMinimisedBanner(banner, result, fingerprint = "") {
  const level = toDisplayLevel(result.risk_level);

  banner.className = `gpd-banner gpd-minimised ${riskClass(level)}`;
  banner.tabIndex = 0;
  banner.setAttribute("aria-label", `Risk: ${level}. Click to expand phishing warning.`);
  banner.innerHTML = "";

  const shield = document.createElement("span");
  shield.className = "gpd-pill-shield";
  shield.setAttribute("aria-hidden", "true");

  const label = document.createElement("span");
  label.className = "gpd-pill-label";
  label.textContent = `Risk: ${level}`;

  banner.append(shield, label);

  // Restore logic: the minimised pill is clickable, but drag movement suppresses
  // the click fired after pointerup so dragging does not accidentally expand it.
  banner.onclick = () => {
    if (suppressNextPillClick) {
      return;
    }
    renderFullBanner(banner, result, fingerprint);
  };

  banner.onkeydown = (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      renderFullBanner(banner, result, fingerprint);
    }
  };

  enableBannerDrag(banner, banner);
  applyBannerPosition(banner, false);
}

function renderBackendError(error) {
  console.warn("AI Phishing Risk Assistant:", error);
  renderBanner({
    risk_level: "medium",
    risk_score: 0,
    reasons: [
      "Unable to reach the local backend at http://localhost:8000.",
      "Start the FastAPI server and reopen or change the Gmail message."
    ]
  });
}

async function analyseOpenedEmail() {
  const payload = extractOpenedEmail();

  if (!payload.email_text && payload.links.length === 0) {
    return;
  }

  const fingerprint = buildFingerprint(payload);
  if (fingerprint === lastAnalysedFingerprint) {
    return;
  }

  if (
    fingerprint === lastFailedFingerprint &&
    Date.now() - lastFailedAt < RETRY_DELAY_MS
  ) {
    return;
  }

  lastAnalysedFingerprint = fingerprint;

  if (currentRequestController) {
    currentRequestController.abort();
  }

  const requestController = new AbortController();
  currentRequestController = requestController;

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload),
      signal: requestController.signal
    });

    if (!response.ok) {
      throw new Error(`Backend returned HTTP ${response.status}`);
    }

    const result = await response.json();
    lastFailedFingerprint = "";
    lastFailedAt = 0;
    renderBanner(result, fingerprint);
  } catch (error) {
    if (error.name === "AbortError") return;
    lastAnalysedFingerprint = "";
    lastFailedFingerprint = fingerprint;
    lastFailedAt = Date.now();
    renderBackendError(error);
  } finally {
    if (currentRequestController === requestController) {
      currentRequestController = null;
    }
  }
}

function scheduleAnalysis() {
  window.clearTimeout(analysisTimer);
  analysisTimer = window.setTimeout(analyseOpenedEmail, ANALYSIS_DELAY_MS);
}

function observeGmailChanges() {
  const observer = new MutationObserver((mutations) => {
    const onlyBannerChanged = mutations.every((mutation) => {
      const target = mutation.target;
      if (target instanceof Element && target.closest(`#${BANNER_ID}`)) {
        return true;
      }

      return Array.from(mutation.addedNodes)
        .concat(Array.from(mutation.removedNodes))
        .every((node) => {
          if (!(node instanceof Element)) return true;
          return node.id === BANNER_ID || Boolean(node.closest(`#${BANNER_ID}`));
        });
    });

    if (!onlyBannerChanged) {
      scheduleAnalysis();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  window.addEventListener("hashchange", scheduleAnalysis);
  window.addEventListener("resize", () => {
    const banner = document.getElementById(BANNER_ID);
    if (banner) {
      applyBannerPosition(banner, true);
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) scheduleAnalysis();
  });

  scheduleAnalysis();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", observeGmailChanges, { once: true });
} else {
  observeGmailChanges();
}
