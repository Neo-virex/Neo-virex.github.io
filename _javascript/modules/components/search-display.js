/**
 * This script makes #search-result-wrapper switch to unload or shown automatically.
 */

const btnSbTrigger = document.getElementById('sidebar-trigger');
const btnSearchTrigger = document.getElementById('search-trigger');
const btnCancel = document.getElementById('search-cancel');
const content = document.querySelectorAll('#main-wrapper>.container>.row');
const topbarTitle = document.getElementById('topbar-title');
const searchWrapper = document.getElementById('search-wrapper');
const search = document.getElementById('search');
const resultWrapper = document.getElementById('search-result-wrapper');
const results = document.getElementById('search-results');
const input = document.getElementById('search-input');
const hints = document.getElementById('search-hints');

// CSS class names
const LOADED = 'd-block';
const UNLOADED = 'd-none';
const FOCUS = 'input-focus';
const FLEX = 'd-flex';

/* Actions in mobile screens (Sidebar hidden) */
class MobileSearchBar {
  static on() {
    if (!searchWrapper || !btnCancel) {
      return;
    }

    searchWrapper.classList.add('search-mode');
    btnCancel.classList.add(LOADED);
  }

  static off() {
    if (!searchWrapper || !btnCancel) {
      return;
    }

    searchWrapper.classList.remove('search-mode');
    btnCancel.classList.remove(LOADED);
  }
}

class ResultSwitch {
  static resultVisible = false;

  static on() {
    if (!this.resultVisible) {
      resultWrapper.classList.remove(UNLOADED);
      content.forEach((el) => {
        el.classList.add(UNLOADED);
      });
      this.resultVisible = true;
    }
  }

  static off() {
    if (this.resultVisible) {
      results.innerHTML = '';

      if (hints.classList.contains(UNLOADED)) {
        hints.classList.remove(UNLOADED);
      }

      resultWrapper.classList.add(UNLOADED);
      content.forEach((el) => {
        el.classList.remove(UNLOADED);
      });
      input.value = '';
      this.resultVisible = false;
    }
  }
}

function isMobileView() {
  return window.innerWidth < 992;
}

export function displaySearch() {
  if (!search || !input || !resultWrapper || !results || !hints) {
    return;
  }

  btnSearchTrigger?.addEventListener('click', () => {
    MobileSearchBar.on();
    ResultSwitch.on();
    input.focus();
  });

  btnCancel?.addEventListener('click', () => {
    MobileSearchBar.off();
    ResultSwitch.off();
  });

  input.addEventListener('focus', () => {
    search.classList.add(FOCUS);
  });

  input.addEventListener('focusout', () => {
    search.classList.remove(FOCUS);
  });

  input.addEventListener('input', () => {
    if (input.value === '') {
      if (isMobileView()) {
        hints.classList.remove(UNLOADED);
      } else {
        ResultSwitch.off();
      }
    } else {
      ResultSwitch.on();
      if (isMobileView()) {
        hints.classList.add(UNLOADED);
      }
    }
  });

  window.addEventListener('resize', () => {
    if (!isMobileView()) {
      MobileSearchBar.off();
    }
  });
}
