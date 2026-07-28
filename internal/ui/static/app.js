// orxies — progressive-enhancement script. Vanilla JS, no frameworks.
// Handles: live-poll partials, expandable site rows (poll-safe), the
// mobile nav, confirm guards, button loading states, deploy progress,
// and the save toast.

(function () {
  // ── expandable site rows + domain-group dropdowns ──────────────────
  // (open state survives the 3s poll swap)
  var openRows = new Set();   // site-detail rows, keyed by filename
  var openGroups = new Set(); // domain groups, keyed by parent domain

  function applyRowState(container) {
    container.querySelectorAll(".site-detail").forEach(function (d) {
      var f = d.getAttribute("data-for");
      var open = openRows.has(f);
      d.classList.toggle("open", open);
      var t = container.querySelector('[data-expand="' + f + '"]');
      if (t) t.setAttribute("aria-expanded", open ? "true" : "false");
    });
    container.querySelectorAll("tr.group-child").forEach(function (row) {
      row.classList.toggle("open", openGroups.has(row.getAttribute("data-group")));
    });
    container.querySelectorAll(".group-toggle").forEach(function (t) {
      t.setAttribute("aria-expanded", openGroups.has(t.getAttribute("data-group")) ? "true" : "false");
    });
  }

  // ── deploy/provision progress: reload once when the log finishes ──
  var reloadedOnDone = false;
  var doneRe = /=== DEPLOY OK ===|=== DEPLOY FAILED|=== SERVICE READY ===|=== PROVISION FAILED/;

  function checkDone(el) {
    if (!doneRe.test(el.textContent || "")) return;
    var prog = document.querySelector("[data-progress].active");
    if (prog && !reloadedOnDone) {
      reloadedOnDone = true;
      setTimeout(function () { window.location.reload(); }, 700);
    }
  }

  // ── live-poll [data-poll-url] elements ─────────────────────────────
  function pollOnce(el, after) {
    fetch(el.dataset.pollUrl, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) { if (html != null) { el.innerHTML = html; if (after) after(el); } })
      .catch(function () { /* swallow; next tick retries */ });
  }
  document.querySelectorAll("[data-poll-url]").forEach(function (el) {
    var ms = parseInt(el.dataset.pollMs || "3000", 10);
    var after = el.id === "site-rows" ? applyRowState
      : el.classList.contains("logbox") ? checkDone
      : null;
    pollOnce(el, after);
    setInterval(function () { pollOnce(el, after); }, ms);
  });

  // ── toggle groups + row details on click (event delegation) ────────
  document.addEventListener("click", function (e) {
    var container = document.getElementById("site-rows");
    var gh = e.target.closest("tr.group-head");
    if (gh) {
      e.preventDefault();
      var gp = gh.getAttribute("data-group");
      if (openGroups.has(gp)) openGroups.delete(gp); else openGroups.add(gp);
      if (container) applyRowState(container);
      return;
    }
    var t = e.target.closest("[data-expand]");
    if (!t) return;
    e.preventDefault();
    var f = t.getAttribute("data-expand");
    if (openRows.has(f)) openRows.delete(f); else openRows.add(f);
    if (container) applyRowState(container);
  });

  // ── mobile nav toggle ──────────────────────────────────────────────
  var toggle = document.querySelector("[data-nav-toggle]");
  var nav = document.querySelector("[data-nav]");
  if (toggle && nav) {
    toggle.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", function (e) {
      if (!nav.classList.contains("open")) return;
      if (nav.contains(e.target) || toggle.contains(e.target)) return;
      nav.classList.remove("open");
      toggle.setAttribute("aria-expanded", "false");
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && nav.classList.contains("open")) {
        nav.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
        toggle.focus();
      }
    });
  }

  // ── confirm guard + button loading on submit ───────────────────────
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
      return;
    }
    var btn = e.submitter || form.querySelector("button[type=submit], button:not([type])");
    if (btn && !btn.classList.contains("btn-noload")) {
      btn.classList.add("loading");
      btn.disabled = true; // form has already begun submitting; navigation follows
    }
  });

  // ── auto-dismissing toast ───────────────────────────────────────────
  var toast = document.querySelector("[data-autotoast]");
  if (toast) {
    requestAnimationFrame(function () { toast.classList.add("show"); });
    setTimeout(function () { toast.classList.remove("show"); }, 3000);
  }

  // ── light / dark theme toggle ───────────────────────────────────────
  var root = document.documentElement;
  function themeNow() {
    return root.getAttribute("data-theme") ||
      (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  }
  function setThemeIcon(t) {
    var u = document.querySelector("[data-theme-toggle] use");
    if (u) u.setAttribute("href", "/static/icons.svg#i-" + (t === "dark" ? "sun" : "moon"));
  }
  setThemeIcon(themeNow());
  var themeBtn = document.querySelector("[data-theme-toggle]");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var t = themeNow() === "dark" ? "light" : "dark";
      try { localStorage.setItem("orxies-theme", t); } catch (e) {}
      root.setAttribute("data-theme", t);
      setThemeIcon(t);
    });
  }
})();
