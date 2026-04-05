// Animate risk bar on load
document.addEventListener("DOMContentLoaded", () => {
  const fill = document.querySelector(".risk-fill");
  if (fill) {
    const width = fill.style.width;
    fill.style.width = "0%";
    setTimeout(() => { fill.style.width = width; }, 100);
  }
});