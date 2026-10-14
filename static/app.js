(function () {
  "use strict";

  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute("content") : "";

  /* -------- Theme toggle (dark default, persisted) -------- */
  var root = document.documentElement;
  var themeToggle = document.getElementById("theme-toggle");
  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    if (themeToggle) {
      themeToggle.textContent = theme === "light" ? "Dark mode" : "Light mode";
      themeToggle.setAttribute("aria-label", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
    }
  }
  var stored = null;
  try { stored = localStorage.getItem("soar-theme"); } catch (e) {}
  if (stored === "light" || stored === "dark") {
    applyTheme(stored);
  }
  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      applyTheme(next);
      try { localStorage.setItem("soar-theme", next); } catch (e) {}
    });
  }

  /* -------- Live alert ingestion (webhook test) -------- */
  var ingestBtn = document.getElementById("ingest-test");
  if (ingestBtn) {
    ingestBtn.addEventListener("click", function () {
      var out = document.getElementById("ingest-result");
      var tokenEl = document.getElementById("ingest-token");
      var token = tokenEl ? tokenEl.textContent.trim() : "";
      if (out) { out.textContent = "Sending test alert…"; }
      fetch("/api/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Ingest-Token": token },
        body: JSON.stringify({
          title: "Suspicious PowerShell from 203.0.113.9",
          severity: "Critical",
          source: "Endpoint Alert",
          details: "Process launched obfuscated PowerShell and contacted login-secure-alert.zip"
        })
      }).then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data.error || "Ingest failed");
          if (out) {
            out.textContent = "Created case #" + data.incident_id + " · " + data.indicators +
              " indicator(s) · suggested: " + (data.suggested_playbook || "none") + ". ";
            var link = document.createElement("a");
            link.href = "/incidents/" + data.incident_id;
            link.textContent = "Open case";
            out.appendChild(link);
          }
        });
      }).catch(function (err) {
        if (out) { out.textContent = "Could not send test alert: " + err.message; }
      });
    });
  }

  /* -------- Assistant panel -------- */
  var panel = document.getElementById("assistant-panel");
  var openBtn = document.getElementById("assistant-toggle");
  var closeBtn = document.getElementById("assistant-close");
  var form = document.getElementById("assistant-form");
  var input = document.getElementById("assistant-input");
  var log = document.getElementById("assistant-messages");

  function setPanel(open) {
    if (!panel || !openBtn) return;
    panel.hidden = !open;
    openBtn.setAttribute("aria-expanded", String(open));
    if (open && input) { input.focus(); }
  }
  if (openBtn) openBtn.addEventListener("click", function () { setPanel(panel.hidden); });
  if (closeBtn) closeBtn.addEventListener("click", function () { setPanel(false); });

  function addMessage(text, who) {
    if (!log) return;
    var p = document.createElement("p");
    p.className = "assistant-message " + who;
    p.textContent = text;
    log.appendChild(p);
    log.scrollTop = log.scrollHeight;
  }

  if (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var message = input ? input.value.trim() : "";
      if (!message) return;
      addMessage(message, "user");
      if (input) input.value = "";
      fetch("/api/assistant", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ message: message })
      }).then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data.error || "Request failed");
          addMessage(data.reply || "(no response)", "bot");
        });
      }).catch(function () {
        addMessage("The assistant is unavailable right now. Please try again.", "error");
      });
    });
  }

  /* -------- Playbook dry-run previews -------- */
  var previewForms = document.querySelectorAll(".playbook-form");
  Array.prototype.forEach.call(previewForms, function (pbForm) {
    pbForm.addEventListener("submit", function (event) {
      event.preventDefault();
      var feedback = pbForm.querySelector(".form-feedback");
      var action = pbForm.getAttribute("action");
      if (feedback) { feedback.textContent = "Preparing dry-run preview…"; feedback.setAttribute("data-state", "loading"); }
      fetch(action, {
        method: "POST",
        headers: { "X-CSRF-Token": csrf }
      }).then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data.error || "Preview failed");
          var preview = document.getElementById("playbook-preview");
          var title = document.getElementById("preview-title");
          var steps = document.getElementById("preview-steps");
          if (title) title.textContent = (data.name || "Workflow preview") + " · " + (data.mode || "dry-run");
          if (steps) {
            steps.textContent = "";
            (data.steps || []).forEach(function (step) {
              var li = document.createElement("li");
              li.textContent = step;
              steps.appendChild(li);
            });
          }
          if (preview) {
            preview.hidden = false;
            if (preview.scrollIntoView) preview.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
          if (feedback) { feedback.textContent = "Dry-run preview ready. No actions executed."; feedback.setAttribute("data-state", "ok"); }
        });
      }).catch(function () {
        if (feedback) { feedback.textContent = "Could not generate preview. Please try again."; feedback.setAttribute("data-state", "error"); }
      });
    });
  });
})();