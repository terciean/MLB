const tierData = {
  1: {
    title: "Level 1: Load-shedding Essentials",
    description:
      "Ideal for homes that want dependable lighting, internet, phone charging, and TV runtime during scheduled outages.",
    bestFor: "Core circuits only",
    upgradePath: "Easy to expand later",
    points: [
      "Short outage resilience for core circuits",
      "Compact inverter and battery footprint",
      "Good entry point for phased upgrades later",
    ],
  },
  2: {
    title: "Level 2: Comfort Backup",
    description:
      "A practical middle ground for households that want to keep a fridge and a few daily-use appliances running with less disruption.",
    bestFor: "Comfort essentials",
    upgradePath: "Great bridge to solar",
    points: [
      "Supports a wider set of essential circuits",
      "Designed for daily convenience and food storage",
      "Suitable for clients planning gradual solar expansion",
    ],
  },
  3: {
    title: "Level 3: Full Off-Grid Readiness",
    description:
      "Best for customers wanting deep resilience across high-load items like geysers, stoves, workshops, or larger home energy demands.",
    bestFor: "Heavy-load resilience",
    upgradePath: "Tailored full-system design",
    points: [
      "Built for longer runtime and heavier loads",
      "Ideal for advanced solar and battery system planning",
      "Tailored design required based on property usage",
    ],
  },
};

const buttons = document.querySelectorAll(".tier-button");
const result = document.getElementById("tier-result");
const menuToggle = document.querySelector(".menu-toggle");
const navLinks = document.getElementById("primary-nav");

function renderTier(tier) {
  const selected = tierData[tier];

  result.innerHTML = `
    <p class="eyebrow">Recommended starting point</p>
    <h3>${selected.title}</h3>
    <p>${selected.description}</p>
    <div class="result-specs">
      <div><span>Best For</span><strong>${selected.bestFor}</strong></div>
      <div><span>Upgrade Path</span><strong>${selected.upgradePath}</strong></div>
    </div>
    <ul>
      ${selected.points.map((point) => `<li>${point}</li>`).join("")}
    </ul>
    <a class="button result-cta" href="#contact">Ask for a Backup Quote</a>
  `;

  buttons.forEach((button) => {
    const isActive = button.dataset.tier === tier;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });
}

buttons.forEach((button) => {
  button.addEventListener("click", () => renderTier(button.dataset.tier));
});

if (menuToggle && navLinks) {
  menuToggle.addEventListener("click", () => {
    const isOpen = menuToggle.classList.toggle("is-open");
    navLinks.classList.toggle("is-open", isOpen);
    menuToggle.setAttribute("aria-expanded", String(isOpen));
  });

  navLinks.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      menuToggle.classList.remove("is-open");
      navLinks.classList.remove("is-open");
      menuToggle.setAttribute("aria-expanded", "false");
    });
  });
}
