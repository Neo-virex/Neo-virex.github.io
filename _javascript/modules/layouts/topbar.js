import { displaySearch } from '../components/search-display';

export function initTopbar() {
  displaySearch();

  const topbarWrapper = document.getElementById('topbar-wrapper');

  if (!topbarWrapper) {
    return;
  }

  let lastScrollY = window.scrollY;

  const syncTopbar = () => {
    const currentScrollY = window.scrollY;
    const isScrollingDown = currentScrollY > lastScrollY;
    const shouldHide = isScrollingDown && currentScrollY > 96;

    topbarWrapper.classList.toggle('topbar-hidden', shouldHide);
    lastScrollY = currentScrollY;
  };

  window.addEventListener('scroll', syncTopbar, { passive: true });
  syncTopbar();
}
