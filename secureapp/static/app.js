(function () {
  "use strict";

  var root = document.documentElement;

  var EYE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  var EYE_OFF = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M17.9 17.9A10.8 10.8 0 0 1 12 19C5 19 1 12 1 12a19.8 19.8 0 0 1 5.1-5.9M9.9 5.2A10 10 0 0 1 12 5c7 0 11 7 11 7a19.9 19.9 0 0 1-2.9 4.1M1 1l22 22"/><path d="M14.1 14.1a3 3 0 1 1-4.2-4.2"/></svg>';
  var COPY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

  var themeButton = document.getElementById("theme");
  if (themeButton) {
    var label = function () {
      var dark = root.getAttribute("data-theme") === "dark";
      themeButton.setAttribute("aria-label", dark ? "Switch to light" : "Switch to dark");
      themeButton.title = dark ? "Switch to light" : "Switch to dark";
    };
    label();
    themeButton.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("safebook-theme", next); } catch (e) {}
      label();
    });
  }

  document.addEventListener("click", function (event) {
    var opener = event.target.closest("[data-explain]");
    if (opener) {
      var dialog = document.getElementById("x-" + opener.dataset.explain);
      if (dialog && dialog.showModal) dialog.showModal();
      return;
    }
    if (event.target.closest(".x-close")) {
      event.target.closest("dialog").close();
      return;
    }
    if (event.target.closest(".dismiss")) {
      event.target.closest("li").remove();
    }
  });
  document.querySelectorAll("dialog.explain").forEach(function (dialog) {
    dialog.addEventListener("click", function (event) {
      if (event.target === dialog) dialog.close();
    });
  });

  document.querySelectorAll('input[type="password"]').forEach(function (input) {
    var wrap = document.createElement("span");
    wrap.className = "pw-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    var eye = document.createElement("button");
    eye.type = "button";
    eye.className = "pw-eye";
    eye.setAttribute("aria-label", "Show password");
    eye.setAttribute("aria-pressed", "false");
    eye.innerHTML = EYE;
    eye.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      eye.innerHTML = show ? EYE_OFF : EYE;
      eye.setAttribute("aria-label", show ? "Hide password" : "Show password");
      eye.setAttribute("aria-pressed", show ? "true" : "false");
      input.focus();
    });
    wrap.appendChild(eye);
  });

  document.querySelectorAll(".fingerprint").forEach(function (box) {
    if (!navigator.clipboard) return;
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy-btn";
    button.innerHTML = COPY + "<span>Copy</span>";
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(box.textContent.trim()).then(function () {
        button.querySelector("span").textContent = "Copied";
        setTimeout(function () { button.querySelector("span").textContent = "Copy"; }, 1600);
      });
    });
    box.insertAdjacentElement("afterend", button);
  });

  document.addEventListener("click", function (event) {
    document.querySelectorAll("details.menu[open]").forEach(function (menu) {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    document.querySelectorAll("details.menu[open]").forEach(function (menu) {
      menu.removeAttribute("open");
      menu.querySelector("summary").focus();
    });
  });

  var hint = document.querySelector("[data-aud-hint]");
  if (hint) {
    document.querySelectorAll('.aud-pick input[name="audience"]').forEach(function (radio) {
      radio.addEventListener("change", function () { hint.textContent = radio.dataset.hint; });
    });
  }

  document.querySelectorAll("form[data-like]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var button = form.querySelector("button");
      fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        headers: { "X-Requested-With": "fetch" },
        credentials: "same-origin"
      }).then(function (response) {
        if (!response.ok) throw new Error(response.status);
        return response.json();
      }).then(function (data) {
        button.classList.toggle("liked", data.liked);
        button.setAttribute("aria-pressed", data.liked ? "true" : "false");
        var count = form.closest(".post").querySelector("[data-like-count]");
        var heart = button.querySelector("svg").outerHTML;
        count.innerHTML = data.count ? heart + " " + data.count : "";
      }).catch(function () { form.submit(); });
    });
  });

  var bubbles = document.getElementById("bubbles");
  if (bubbles) bubbles.scrollTop = bubbles.scrollHeight;
  document.querySelectorAll(".composer-line textarea, .composer textarea").forEach(function (area) {
    var grow = function () {
      area.style.height = "auto";
      area.style.height = Math.min(area.scrollHeight, 200) + "px";
    };
    area.addEventListener("input", grow);
    if (area.closest(".composer-line")) {
      area.addEventListener("keydown", function (event) {
        if (event.key === "Enter" && !event.shiftKey && area.value.trim()) {
          event.preventDefault();
          area.form.submit();
        }
      });
    }
  });

  var meter = document.querySelector("[data-strength-for]");
  if (meter) {
    var target = document.getElementById(meter.getAttribute("data-strength-for"));
    var text = meter.querySelector(".strength-text");
    target.closest(".field").appendChild(meter);
    meter.hidden = false;
    var human = function (seconds) {
      var units = [["years", 31557600], ["days", 86400], ["hours", 3600], ["minutes", 60]];
      if (seconds > 31557600 * 1e6) return "more than a million years";
      for (var i = 0; i < units.length; i++) {
        if (seconds >= units[i][1]) return "about " + Math.round(seconds / units[i][1]).toLocaleString() + " " + units[i][0];
      }
      return "under a minute";
    };
    var judge = function () {
      var p = target.value;
      if (!p) { meter.setAttribute("data-level", "0"); text.textContent = "Longer is better than clever. A short sentence works well."; return; }
      var pool = 0;
      if (/[a-z]/.test(p)) pool += 26;
      if (/[A-Z]/.test(p)) pool += 26;
      if (/[0-9]/.test(p)) pool += 10;
      if (/[^A-Za-z0-9]/.test(p)) pool += 33;
      var bits = p.length * Math.log2(Math.max(pool, 2));
      if (/^(.)\1+$/.test(p) || /password|123456|qwerty|safebook/i.test(p)) bits = Math.min(bits, 12);
      var seconds = Math.pow(2, bits - 1) / 4000;
      var level = bits < 36 ? 1 : bits < 50 ? 2 : bits < 64 ? 3 : 4;
      meter.setAttribute("data-level", String(level));
      text.textContent = ["", "Weak", "Fair", "Strong", "Very strong"][level] + ": " + human(seconds) + " for a thousand machines to guess.";
    };
    target.addEventListener("input", judge);
    judge();
  }

  var signOut = document.getElementById("signOut");
  if (signOut) {
    var IDLE = 15 * 60 * 1000;
    var timer;
    var arm = function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        signOut.querySelector('input[name="reason"]').value = "idle";
        signOut.submit();
      }, IDLE);
    };
    ["keydown", "mousedown", "scroll", "touchstart"].forEach(function (name) {
      window.addEventListener(name, arm, { passive: true });
    });
    arm();
  }
})();
