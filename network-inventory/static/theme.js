const savedTheme = localStorage.getItem("netscope-theme");
const initialTheme = savedTheme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
document.documentElement.dataset.theme = initialTheme;

window.addEventListener("DOMContentLoaded", () => {
  const toggle = document.querySelector("#themeToggle");
  if (!toggle) return;

  function updateToggle() {
    const dark = document.documentElement.dataset.theme === "dark";
    toggle.setAttribute("aria-pressed", String(dark));
    toggle.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    toggle.title = dark ? "Switch to light mode" : "Switch to dark mode";
  }

  toggle.addEventListener("click", () => {
    const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = nextTheme;
    localStorage.setItem("netscope-theme", nextTheme);
    updateToggle();
  });

  updateToggle();
});
