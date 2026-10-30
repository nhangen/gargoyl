// Applies hrefs from config.js and flags placeholder links so they can't ship unnoticed.
(function () {
  var links = window.GARGOYL_LINKS || {};

  document.querySelectorAll("[data-link]").forEach(function (el) {
    var url = links[el.getAttribute("data-link")];
    if (!url) return;
    el.setAttribute("href", url);
    if (/^https?:\/\//.test(url)) el.setAttribute("rel", "noopener");

    if (url.indexOf("REPLACE_ME") !== -1) {
      el.classList.add("is-placeholder");
      el.setAttribute("title", "Placeholder URL: set the real link in config.js before publishing");
      var tag = document.createElement("span");
      tag.className = "placeholder-tag";
      tag.textContent = "placeholder URL";
      el.appendChild(tag);
    }
  });
})();
