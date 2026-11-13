// Loaded synchronously in <head> so the saved theme applies before first paint.
(function () {
  var saved = null;
  try { saved = localStorage.getItem("maldetect-theme"); } catch (e) { /* storage blocked */ }
  var theme = saved === "light" || saved === "dark"
    ? saved
    : (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.dataset.theme = theme;
})();
