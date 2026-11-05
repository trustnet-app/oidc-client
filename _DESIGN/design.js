(function () {
  "use strict";

  var STORAGE_KEY = "demo-rp-theme";

  function storedTheme() {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      return null;
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].textContent = theme === "dark" ? "Light" : "Dark";
      buttons[i].setAttribute("aria-label", "Switch to " + (theme === "dark" ? "light" : "dark") + " theme");
    }
  }

  function currentTheme() {
    var explicit = document.documentElement.getAttribute("data-theme");
    if (explicit) return explicit;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function initTheme() {
    applyTheme(storedTheme() || currentTheme());
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        try {
          localStorage.setItem(STORAGE_KEY, next);
        } catch (e) {}
        applyTheme(next);
      });
    }
  }

  function initProbe() {
    var buttons = document.querySelectorAll("[data-probe]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function () {
        var target = document.getElementById(this.getAttribute("data-probe"));
        if (!target) return;
        var hidden = target.hasAttribute("hidden");
        if (hidden) target.removeAttribute("hidden");
        else target.setAttribute("hidden", "");
      });
    }
  }

  function initCopy() {
    var buttons = document.querySelectorAll("[data-copy]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function () {
        var target = document.getElementById(this.getAttribute("data-copy"));
        if (!target || !navigator.clipboard) return;
        navigator.clipboard.writeText(target.textContent || "").then(function () {
          var old = this.textContent;
          this.textContent = "Copied";
          setTimeout(function () { this.textContent = old; }.bind(this), 1200);
        }.bind(this));
      });
    }
  }

  function initReset() {
    var buttons = document.querySelectorAll("[data-reset]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function (event) {
        event.preventDefault();
        var note = document.getElementById("reset-note");
        if (note) {
          note.removeAttribute("hidden");
          setTimeout(function () { note.setAttribute("hidden", ""); }, 1800);
        }
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initProbe();
    initCopy();
    initReset();
  });
})();
