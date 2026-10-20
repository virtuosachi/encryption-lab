/**
 * guide.js — the small bit of browser JavaScript behind "guided mode".
 *
 * All the encryption happens in PHP on the server. This file only:
 *   1. remembers which steps you ticked as finished (saved in your browser's localStorage),
 *   2. shows the progress bar on each lesson and on the home page,
 *   3. checks the quiz answers,
 *   4. sends forms WITHOUT reloading the page: it posts the form in the background
 *      (fetch), and swaps in only the step you're working on, so the page never jumps.
 *
 * If JavaScript is off (or something goes wrong), forms still work the classic way:
 * the whole page reloads with the result.
 */
(function () {
  const page = document.body.dataset.page || 'index.php';

  // localStorage can be unavailable (private windows, blocked cookies) — never crash because of it.
  const store = {
    get(key) { try { return localStorage.getItem(key); } catch { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch { /* ignore */ } },
  };

  /* ---------- 1 + 2: step progress on lesson pages ---------- */
  const allSteps = () => Array.from(document.querySelectorAll('[data-step]'));

  function updateProgress() {
    const steps = allSteps();
    if (!steps.length) return;
    const done = steps.filter((s) => s.classList.contains('is-done')).length;
    const bar = document.querySelector('[data-progress] .progress-bar span');
    const text = document.querySelector('[data-progress-text]');
    if (bar) bar.style.width = (done / steps.length) * 100 + '%';
    if (text) text.textContent = `${done} of ${steps.length}`;
    store.set(`lab:${page}:total`, String(steps.length));
    store.set(`lab:${page}:done`, String(done));
  }

  /** Restore + wire up the "I finished this step" checkbox of one step card. */
  function initDoneCheckbox(step) {
    const box = step.querySelector('[data-done]');
    if (!box) return;
    const key = `lab:${page}:${step.dataset.step}`;
    box.checked = store.get(key) === '1';
    step.classList.toggle('is-done', box.checked);
    box.addEventListener('change', () => {
      store.set(key, box.checked ? '1' : '0');
      step.classList.toggle('is-done', box.checked);
      updateProgress();
    });
  }

  allSteps().forEach(initDoneCheckbox);
  updateProgress();

  /* ---------- home page: show progress for each lesson ---------- */
  document.querySelectorAll('[data-lesson]').forEach((el) => {
    const file = el.dataset.lesson;
    const total = Number(store.get(`lab:${file}:total`) || 0);
    const done = Number(store.get(`lab:${file}:done`) || 0);
    const badge = el.querySelector('[data-lesson-status]');
    if (!badge) return;
    if (total && done >= total) { badge.textContent = 'Completed'; badge.className = 'badge good'; }
    else if (done > 0) { badge.textContent = `${done} of ${total} steps`; badge.className = 'badge warn'; }
  });

  /* ---------- 3: quiz ---------- */
  document.querySelectorAll('.q').forEach((q) => {
    const correct = Number(q.dataset.correct);
    const why = q.querySelector('.why');
    const explanation = why.innerHTML; // remember the explanation written in PHP
    q.querySelectorAll('.opt').forEach((btn) => {
      btn.addEventListener('click', () => {
        q.querySelectorAll('.opt').forEach((b) => b.classList.remove('right', 'wrong'));
        const isRight = Number(btn.dataset.i) === correct;
        btn.classList.add(isRight ? 'right' : 'wrong');
        why.hidden = false;
        why.className = 'why ' + (isRight ? 'is-right' : 'is-wrong');
        why.innerHTML = isRight ? '<b>Correct!</b> ' + explanation : '<b>Not quite.</b> Try another answer.';
      });
    });
  });

  /* ---------- 4: submit forms without reloading the page ---------- */

  /**
   * Find the button in the new card that matches the one that was clicked.
   * Returns null when we can't be sure (e.g. the clicked "Delete" button's row is gone);
   * then we anchor on the step card instead.
   */
  function findSameButton(card, button, index, oldCount) {
    if (!button) return null;
    const buttons = Array.from(card.querySelectorAll('button'));
    const byAction = buttons.filter((b) => b.name && b.name === button.name && b.value === button.value);
    if (byAction.length === 1) return byAction[0];
    if (buttons.length === oldCount && buttons[index]) return buttons[index];
    return null;
  }

  // One listener on the whole document catches every form, including forms inside
  // step cards that get swapped in later (this is called "event delegation").
  document.addEventListener('submit', async (event) => {
    const form = event.target;
    const step = form.closest('[data-step]');
    if (!step || !window.fetch || !window.DOMParser) return; // let the browser do a normal submit

    event.preventDefault();
    const button = event.submitter;

    // Collect the form fields, plus the name/value of the button that was clicked
    // (several forms use different buttons for different actions).
    const data = new FormData(form);
    if (button && button.name) data.set(button.name, button.value);

    // Show that something is happening.
    const originalLabel = button ? button.textContent : '';
    if (button) { button.disabled = true; button.textContent = 'Working…'; }
    step.classList.add('is-loading');

    try {
      const response = await fetch(form.getAttribute('action') || window.location.pathname, {
        method: 'POST',
        body: data,
      });
      const html = await response.text();
      const newDoc = new DOMParser().parseFromString(html, 'text/html');
      const newStep = newDoc.getElementById(step.id);
      if (!newStep) throw new Error('Step not found in response');

      // Some pages print errors above the steps. Move them into this step so they're visible here.
      newDoc.querySelectorAll('main > .notice.error').forEach((err) => {
        const forms = newStep.querySelectorAll('form');
        if (forms.length) forms[forms.length - 1].after(err);   // right under the buttons
        else newStep.insertBefore(err, newStep.querySelector('.done-check'));
      });

      // A few fields are shared between steps (e.g. the ciphertext from step 2 pre-fills step 4).
      newDoc.querySelectorAll('[data-sync]').forEach((el) => {
        if (newStep.contains(el) || !el.value) return;
        const target = document.querySelector(`[data-sync="${el.dataset.sync}"]`);
        if (target && !step.contains(target)) target.value = el.value;
      });

      // Remember exactly where the clicked button is on screen BEFORE swapping…
      const allButtons = Array.from(step.querySelectorAll('button'));
      const buttonIndex = allButtons.indexOf(button);
      const stepTop = step.getBoundingClientRect().top;
      const anchorTop = button ? button.getBoundingClientRect().top : stepTop;

      // Swap the old step card for the new one — the rest of the page stays exactly as it was.
      step.replaceWith(newStep);
      initDoneCheckbox(newStep);
      updateProgress();

      // …then find the same button in the new card and shift the page so it's in the
      // very same spot. Result: the page never jumps, no matter what changed above it.
      const newButton = findSameButton(newStep, button, buttonIndex, allButtons.length);
      const drift = newButton
        ? newButton.getBoundingClientRect().top - anchorTop
        : newStep.getBoundingClientRect().top - stepTop;
      if (drift !== 0) window.scrollBy(0, drift);

      // Highlight the new result. If it's hidden BELOW the screen, glide down just enough
      // to show it. We never scroll up.
      const result = newStep.querySelector('.guide.explain, .output, .notice');
      if (result) {
        result.classList.add('flash');
        const box = result.getBoundingClientRect();
        const visibleBottom = window.innerHeight - 40;
        if (box.top > visibleBottom - 60) {
          window.scrollBy({ top: Math.min(box.top - visibleBottom + 160, box.top - 90), behavior: 'smooth' });
        }
      }

      // Let other scripts (the guided tour) know this step has a fresh result.
      document.dispatchEvent(new CustomEvent('lab:step-updated', { detail: { id: newStep.id } }));
    } catch (err) {
      // Anything unexpected: fall back to a normal full-page submit.
      console.warn('Falling back to a normal form submit:', err);
      if (button) { button.disabled = false; button.textContent = originalLabel; }
      step.classList.remove('is-loading');
      if (button && button.name) {
        const hidden = Object.assign(document.createElement('input'), { type: 'hidden', name: button.name, value: button.value });
        form.appendChild(hidden);
      }
      HTMLFormElement.prototype.submit.call(form);
    }
  });
})();
