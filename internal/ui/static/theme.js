// Applies the saved theme before first paint (no flash). Loaded
// synchronously in <head>; the toggle wiring lives in app.js.
(function () {
  try {
    var t = localStorage.getItem("orxies-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* private mode / disabled storage */ }
})();
