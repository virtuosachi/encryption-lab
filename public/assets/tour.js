/**
 * tour.js — a pop-up guided tour for every page.
 *
 * - The first time a student opens a lesson, a welcome pop-up offers a tour.
 *   They can start it, or skip it ("No thanks"), or turn off automatic tours.
 * - The tour highlights one step card at a time (everything else is dimmed),
 *   shows the instructions in a pop-up, and has Back / Next / Skip buttons.
 * - While a step is highlighted, the student can use its form normally. When the
 *   result appears, the tour moves to the "What just happened?" box and reads it out.
 * - The "Guide me" button (bottom-right corner) restarts the tour at any time,
 *   starting from the step card currently on screen.
 *
 * Keyboard: Right arrow = Next, Left arrow = Back, Esc = Skip.
 * Plain browser JavaScript, no libraries.
 */
(function () {
  const page = document.body.dataset.page || 'index.php';
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
  };
  const SEEN_KEY = `lab:tour:seen:${page}`;
  const AUTO_KEY = 'lab:tour:auto'; // 'off' = don't open tours automatically

  /* -------------------------------------------------------------------
   * 1. Build the list of tour stops from the page itself.
   *    Each stop: { title, html, targets: () => [elements], cardId? }
   *    A stop with no targets is shown as a centered pop-up.
   * ----------------------------------------------------------------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const text = (el) => (el ? el.textContent.trim() : '');

  function buildStops() {
    const stops = [];
    const title = text($('main h1'));
    const nextLink = $('.pager .next');
    const stepCards = Array.from(document.querySelectorAll('section.step[data-step]'));

    if (stepCards.length) {
      // ---- Lesson page ----
      stops.push({
        title,
        html: `<p>${$('.subtitle') ? $('.subtitle').innerHTML : ''}</p>
               <p>This tour takes you through the lesson one step at a time. It shows you what to type and
               which button to press, then explains each result.</p>
               <p class="tour-tip">You can skip it at any time, and restart it later with the <b>Guide me</b> button.</p>`,
        targets: null,
        welcome: true,
      });

      const intro = $('section.intro');
      if (intro) {
        stops.push({
          title: 'Before you start',
          html: `<p>Here's what you'll learn, and the new words used in this lesson. Take a moment to read the definitions. The steps will use them.</p>
                 <p>The green bar shows how many steps you've finished.</p>`,
          targets: () => [$('section.intro')],
        });
      }

      stepCards.forEach((card) => {
        const id = card.id;
        const q = (sel) => $(`#${id} ${sel}`);
        const lead = q('.lead');
        const todo = q('.guide.todo');
        const hasForm = !!q('form');
        stops.push({
          cardId: id,
          title: `${text(q('.step-num'))}: ${text(q('.step-head h2'))}`,
          html: (lead ? `<p>${lead.innerHTML}</p>` : '')
              + (todo ? '<p>Follow the blue <b>What to do</b> box in the highlighted card.</p>' : '')
              + (hasForm
                  ? '<p class="tour-tip">Try it now. When your result appears, the tour will point you to the explanation.</p>'
                  : '<p class="tour-tip">Read this card, then press <b>Next</b>.</p>'),
          // Highlight the instructions and the form (not the whole long card).
          targets: () => [q('.step-head'), q('.lead'), q('.guide.todo'), q('form')].filter(Boolean),
        });
      });

      if ($('section.quiz')) {
        stops.push({
          title: 'Check yourself',
          html: '<p>Finish the lesson with this short quiz. Click an answer and you\'ll see right away if it\'s correct.</p>',
          targets: () => [$('section.quiz')],
        });
      }

      stops.push({
        title: 'Tour finished',
        html: `<p>You've seen every step of this lesson. Remember to tick <b>"I finished this step"</b> on each card as you go.</p>
               ${nextLink ? `<p>When you're ready: <b>${nextLink.textContent.trim()}</b>.</p>` : ''}`,
        targets: null,
        finish: true,
        nextHref: nextLink ? nextLink.getAttribute('href') : null,
      });
    } else {
      // ---- Home page (or any page with data-tour-title sections) ----
      const sections = Array.from(document.querySelectorAll('[data-tour-title]'));
      if (!sections.length) return stops;
      stops.push({
        title: 'Welcome to the Encryption Lab',
        html: '<p>Let\'s take a 30-second look around so you know how everything works.</p><p class="tour-tip">You can skip at any time.</p>',
        targets: null,
        welcome: true,
      });
      sections.forEach((sec, i) => {
        sec.dataset.tourIndex = String(i);
        stops.push({
          title: sec.dataset.tourTitle,
          html: `<p>${sec.dataset.tourText || ''}</p>`,
          targets: () => [$(`[data-tour-index="${i}"]`)],
        });
      });
      stops.push({
        title: 'Ready?',
        html: '<p>Start with lesson 01. Each lesson also has its own tour.</p>',
        targets: null,
        finish: true,
        nextHref: nextLink ? nextLink.getAttribute('href') : null,
      });
    }
    return stops;
  }

  const stops = buildStops();
  if (!stops.length) return;

  /* -------------------------------------------------------------------
   * 2. The pop-up, the dim overlay, the spotlight and the launcher.
   * ----------------------------------------------------------------- */
  const dim = Object.assign(document.createElement('div'), { className: 'tour-dim' });
  const hole = Object.assign(document.createElement('div'), { className: 'tour-hole' });
  const pop = Object.assign(document.createElement('div'), { className: 'tour-pop' });
  pop.setAttribute('role', 'dialog');
  pop.setAttribute('aria-live', 'polite');
  const launcher = Object.assign(document.createElement('button'), {
    className: 'tour-launcher', type: 'button', textContent: 'Guide me',
    title: 'Start the guided tour',
  });
  document.body.append(dim, hole, pop, launcher);

  let index = -1;       // which stop is showing (-1 = tour closed)
  let current = null;   // the stop object being shown (may be a "result" stop)
  let rafId = 0;
  let minimized = false; // tour shrunk to a small pill so it doesn't cover anything

  function unionRect(elements) {
    const rects = elements.map((el) => el.getBoundingClientRect()).filter((r) => r.width || r.height);
    if (!rects.length) return null;
    const top = Math.min(...rects.map((r) => r.top));
    const left = Math.min(...rects.map((r) => r.left));
    const bottom = Math.max(...rects.map((r) => r.bottom));
    const right = Math.max(...rects.map((r) => r.right));
    return { top, left, bottom, right, width: right - left, height: bottom - top };
  }

  function targetRect() {
    if (!current || !current.targets) return null;
    const els = current.targets().filter(Boolean);
    return els.length ? unionRect(els) : null;
  }

  /** Keep the spotlight and pop-up glued to the target, even while scrolling. */
  function position() {
    const r = targetRect();
    const pad = 8;
    const mobile = window.innerWidth < 640;

    if (!r) {
      hole.style.display = 'none';
      dim.classList.add('on');
      pop.classList.add('centered');
      pop.classList.toggle('sheet', false);
      pop.style.top = pop.style.left = '';
    } else {
      dim.classList.remove('on');
      pop.classList.remove('centered');
      hole.style.display = 'block';
      hole.style.top = `${r.top - pad}px`;
      hole.style.left = `${r.left - pad}px`;
      hole.style.width = `${r.width + pad * 2}px`;
      hole.style.height = `${r.height + pad * 2}px`;

      if (minimized) {
        pop.classList.remove('sheet');
        pop.style.top = pop.style.left = '';
      } else if (mobile) {
        pop.classList.add('sheet');
        pop.style.top = pop.style.left = '';
      } else {
        pop.classList.remove('sheet');
        const ph = pop.offsetHeight;
        const pw = pop.offsetWidth;
        const gap = 14;
        let top;
        if (r.bottom + gap + ph < window.innerHeight - 10) top = r.bottom + gap;          // below
        else if (r.top - gap - ph > 70) top = r.top - gap - ph;                            // above
        else top = Math.max(70, window.innerHeight - ph - 16);                             // overlap, bottom of screen
        let left = Math.min(Math.max(16, r.left), window.innerWidth - pw - 16);
        pop.style.top = `${top}px`;
        pop.style.left = `${left}px`;
      }
    }
    rafId = requestAnimationFrame(position);
  }

  /** Scroll so the highlighted area is comfortably visible (only when it isn't already). */
  function bringIntoView() {
    const r = targetRect();
    if (!r) return;
    const headerSpace = 80;
    const roomForPopup = window.innerWidth < 640 ? window.innerHeight * 0.45 : 40;
    const fitsTop = r.top >= headerSpace;
    const fitsBottom = r.top + Math.min(r.height, 260) <= window.innerHeight - roomForPopup;
    if (fitsTop && fitsBottom) return;
    window.scrollBy({ top: r.top - headerSpace, behavior: 'smooth' });
  }

  function render() {
    const total = stops.length;
    const isWelcome = !!current.welcome;
    const isFinish = !!current.finish;
    const counter = current.result ? 'Result' : `${index + 1} of ${total}`;

    pop.innerHTML = `
      <div class="tour-head">
        <span class="tour-count">${counter}</span>
        <span class="tour-mini-title">${current.title}</span>
        <span>
          ${isWelcome || isFinish ? '' : `<button type="button" class="tour-x" data-act="min" aria-label="${minimized ? 'Expand' : 'Minimize'} tour" title="${minimized ? 'Expand' : 'Minimize'}">${minimized ? '+' : '–'}</button>`}
          <button type="button" class="tour-x" data-act="skip" aria-label="Close tour" title="Close tour">×</button>
        </span>
      </div>
      <h3>${current.title}</h3>
      <div class="tour-body">${current.html}</div>
      ${isWelcome ? `<label class="tour-auto"><input type="checkbox" data-act="auto" ${store.get(AUTO_KEY) === 'off' ? 'checked' : ''}> Don't open tours automatically</label>` : ''}
      <div class="tour-actions">
        ${isWelcome
          ? '<button type="button" class="secondary" data-act="skip">No thanks</button><button type="button" data-act="next">Start the tour</button>'
          : isFinish
            ? `<button type="button" class="secondary" data-act="back">Back</button>
               ${current.nextHref ? `<a class="tour-btn" href="${current.nextHref}">Next lesson</a>` : ''}
               <button type="button" data-act="done">Done</button>`
            : `<button type="button" class="link" data-act="skip">Skip tour</button>
               <span class="spacer"></span>
               <button type="button" class="secondary" data-act="back" ${index <= 0 ? 'disabled' : ''}>Back</button>
               <button type="button" data-act="next">Next</button>`}
      </div>`;
    pop.classList.toggle('mini', minimized);
    const firstBtn = pop.querySelector('[data-act="next"], [data-act="done"]');
    if (firstBtn) firstBtn.focus({ preventScroll: true });
  }

  function show(i) {
    index = Math.max(0, Math.min(i, stops.length - 1));
    current = stops[index];
    minimized = false;
    document.body.classList.add('tour-active');
    pop.hidden = false;
    render();
    cancelAnimationFrame(rafId);
    position();
    bringIntoView();
  }

  function close() {
    index = -1;
    current = null;
    cancelAnimationFrame(rafId);
    document.body.classList.remove('tour-active');
    pop.hidden = true;
    hole.style.display = 'none';
    dim.classList.remove('on');
    store.set(SEEN_KEY, '1');
  }

  /* -------------------------------------------------------------------
   * 3. Buttons, keyboard, and reacting to results.
   * ----------------------------------------------------------------- */
  pop.addEventListener('click', (e) => {
    const act = e.target.closest('[data-act]')?.dataset.act;
    if (act === 'next') show(index + 1);
    else if (act === 'back') show(index - 1);
    else if (act === 'again') { current = stops[index]; render(); }
    else if (act === 'min') { minimized = !minimized; render(); }
    else if (act === 'skip' || act === 'done') close();
  });
  pop.addEventListener('change', (e) => {
    if (e.target.dataset.act === 'auto') store.set(AUTO_KEY, e.target.checked ? 'off' : 'on');
  });

  document.addEventListener('keydown', (e) => {
    if (index < 0) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '');
    if (e.key === 'Escape') close();
    else if (!typing && e.key === 'ArrowRight') show(index + 1);
    else if (!typing && e.key === 'ArrowLeft') show(index - 1);
  });

  // When a highlighted step gets a new result (guide.js fires this), explain it.
  document.addEventListener('lab:step-updated', (e) => {
    if (index < 0 || !current || current.cardId !== e.detail.id) return;
    const id = e.detail.id;
    const explain = $(`#${id} .guide.explain`);
    const error = $(`#${id} .notice.error`);
    const output = $(`#${id} .output`);
    current = {
      cardId: id,
      result: true,
      title: error && !explain ? 'Not quite. Let\'s fix it' : 'Your result is ready',
      html: error && !explain
        ? `<p>${error.textContent.trim()}</p><p class="tour-tip">Check the hint in this step and try again.</p>`
        : '<p>Read the green <b>What just happened?</b> box in the highlighted area. It explains your result.</p>'
          + '<p class="tour-tip">Then try the <b>Try this next</b> ideas, or press <b>Next</b> to continue.</p>',
      targets: () => [output ? $(`#${id} .output`) : explain ? $(`#${id} .guide.explain`) : $(`#${id} .notice`)].filter(Boolean),
    };
    minimized = false;
    render();
    // On a result, "Back" returns to this step's instructions instead of the previous step.
    const back = pop.querySelector('[data-act="back"]');
    if (back) { back.disabled = false; back.textContent = 'Instructions'; back.dataset.act = 'again'; }
  });

  // The "Guide me" button: start at the step card currently on screen (or the beginning).
  launcher.addEventListener('click', () => {
    const mid = window.innerHeight / 2;
    const onScreen = stops.findIndex((s) => {
      if (!s.cardId) return false;
      const card = document.getElementById(s.cardId);
      if (!card) return false;
      const r = card.getBoundingClientRect();
      return r.top < mid && r.bottom > mid;
    });
    show(onScreen > 0 ? onScreen : 0);
  });

  // Re-measure when the window changes size.
  window.addEventListener('resize', () => { if (index >= 0) bringIntoView(); });

  pop.hidden = true;

  // First visit to this page? Offer the tour automatically.
  if (!store.get(SEEN_KEY) && store.get(AUTO_KEY) !== 'off') {
    setTimeout(() => show(0), 400);
  }
})();
