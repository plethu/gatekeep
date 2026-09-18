(() => {
    // mdBook 0.5.4's sidebar controller owns visibility and persistence. The build
    // converts its label to a native button; this supplies the label's activation.
    const toggle = document.getElementById("mdbook-sidebar-toggle");
    const checkbox = document.getElementById("mdbook-sidebar-toggle-anchor");
    const sidebar = document.getElementById("mdbook-sidebar");
    if (toggle instanceof HTMLButtonElement && checkbox instanceof HTMLInputElement) {
        toggle.addEventListener("click", () => checkbox.click());
        checkbox.addEventListener("change", () => {
            if (!checkbox.checked && matchMedia("(prefers-reduced-motion: reduce)").matches) {
                sidebar.style.display = "none";
            }
        });
    }
    const search = document.getElementById("mdbook-searchbar");
    const resultCount = document.getElementById("mdbook-searchresults-header");
    if (search && resultCount) {
        search.setAttribute("aria-label", "Search the guides");
        resultCount.setAttribute("role", "status");
        resultCount.setAttribute("aria-atomic", "true");
    }
    const main = document.querySelector("main");
    if (main) {
        main.id = "main-content";
        main.tabIndex = -1;
        const skip = document.createElement("a");
        skip.href = "#main-content";
        skip.className = "skip-to-content";
        skip.textContent = "Skip to content";
        document.body.prepend(skip);
    }

    // Code that scrolls horizontally must be reachable without a pointing device.
    function updateCodeFocus() {
        document.querySelectorAll("pre, pre code").forEach(block => {
            if (block.scrollWidth > block.clientWidth) block.tabIndex = 0;
            else block.removeAttribute("tabindex");
        });
    }
    updateCodeFocus();
    window.addEventListener("resize", updateCodeFocus);
})();
