/* =====================================================================
   Password Generator Pro — app.js
   Cryptographically-secure password & passphrase generation with live
   entropy / strength analysis and a persisted history.
   Classic script (no modules). Depends on window.WUS (core.js).
   ===================================================================== */
(function () {
  'use strict';

  /* ------------------------------------------------------------------ *
   * Constants & character sets
   * ------------------------------------------------------------------ */
  var SETS = {
    upper:  'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower:  'abcdefghijklmnopqrstuvwxyz',
    number: '0123456789',
    symbol: '!@#$%^&*-_=+?.,;:'
  };
  // Symbols available before the "ambiguous" filter removes the tricky ones.
  var SYMBOL_FULL = '!@#$%^&*()-_=+[]{};:,.<>/?\\|~`\'"';
  var SIMILAR = 'Il1O0'.split('');                       // visually similar glyphs
  var AMBIGUOUS = '{}[]()/\\\'"`~,;:.<>|'.split('');      // easily-misread punctuation

  var HISTORY_KEY = 'pwgen.history';
  var SETTINGS_KEY = 'pwgen.settings';
  var MAX_HISTORY = 20;
  var GUESSES_PER_SEC = 1e10; // attacker speed assumption for crack-time estimate

  // Small built-in EFF-style word list (kept short but varied) for passphrases.
  var WORDLIST = (
    'able acid acre army atom aunt away baby back bald band bank barn beam bean bear ' +
    'bell belt bird blue boat bold bone book boot born boss bowl brave bread brick brief ' +
    'broom brush cabin cable cake calm camp cane card cart cave chair chalk charm chase ' +
    'chess chest chief clay clean clear cliff cloak clock cloud clover coal coast coin cold ' +
    'comet coral cork corn craft crane crisp crow crown cube curl daisy dance dawn deer ' +
    'delta diary dock dove draft dream dress drift drum dune dusk eagle earth east echo ' +
    'eel elbow elder elf ember envy fable fairy fang farm fern field film fire flame flask ' +
    'fleet flint flock flour flute foam fog forge fork frost fruit gale gate gem ghost giant ' +
    'glade glass globe glow goat gold grain grape grass green grove gulf hail hand harp ' +
    'hawk haze heart hedge herb hill hive holly honey hood horn ivory ivy jade jazz jewel ' +
    'jolly judge juice keel kelp kite knee knot lake lamp lance leaf ledge lemon lily lime ' +
    'lion lock lotus lunar lynx maple marble mars mask mead melon mint mist moon moss moth ' +
    'mound mouse music nest noble north oak oasis ocean olive onyx opal orbit otter owl palm ' +
    'panda pane peach pearl pebble petal pine pixel plum pond pony pouch prism quartz quest ' +
    'quill rain raven reed reef ridge river robin rock rope rose ruby sage sail salt sand ' +
    'scarf seal shade shark shell shore silk slate sloth smoke snow solar spark spice spire ' +
    'spore stalk star stem stone storm straw surf swan swift table teal thorn tide tiger ' +
    'toad torch tower trail trout tulip tusk twig vale vapor vault vine violet vivid voice ' +
    'wagon wave whale wheat whisk willow wind wolf wood wren yak yarn zebra zest'
  ).split(/\s+/).filter(Boolean);

  var STRENGTH = [
    null,                              // index 0 unused
    { lvl: 1, label: 'Very weak' },
    { lvl: 2, label: 'Weak' },
    { lvl: 3, label: 'Fair' },
    { lvl: 4, label: 'Strong' },
    { lvl: 5, label: 'Excellent' }
  ];

  /* ------------------------------------------------------------------ *
   * Secure randomness helpers (crypto.getRandomValues only)
   * ------------------------------------------------------------------ */

  // Uniform integer in [0, max) via rejection sampling to avoid modulo bias.
  function randomInt(max) {
    if (max <= 0) throw new Error('randomInt: max must be > 0');
    if (max === 1) return 0;
    // Smallest mask covering [0, max)
    var bitsNeeded = Math.ceil(Math.log2(max));
    var bytesNeeded = Math.ceil(bitsNeeded / 8);
    var mask = (1 << bitsNeeded) - 1; // works for max up to 2^31
    var buf = new Uint8Array(bytesNeeded);
    // guard against pathological loops
    for (var attempt = 0; attempt < 1000; attempt++) {
      crypto.getRandomValues(buf);
      var val = 0;
      for (var i = 0; i < bytesNeeded; i++) val = (val << 8) | buf[i];
      val = val & mask;
      if (val < max) return val;
    }
    // Extremely unlikely fallback (still crypto-seeded, slight bias only here)
    var fb = new Uint32Array(1);
    crypto.getRandomValues(fb);
    return fb[0] % max;
  }

  // Pick one random character from a string.
  function pick(pool) {
    return pool.charAt(randomInt(pool.length));
  }

  // Fisher–Yates shuffle using secure randomness.
  function secureShuffle(arr) {
    for (var i = arr.length - 1; i > 0; i--) {
      var j = randomInt(i + 1);
      var tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
    return arr;
  }

  /* ------------------------------------------------------------------ *
   * Character-set assembly
   * ------------------------------------------------------------------ */

  // Apply exclusion filters to a set string.
  function filterSet(str, excludeSimilar, excludeAmbiguous) {
    return str.split('').filter(function (ch) {
      if (excludeSimilar && SIMILAR.indexOf(ch) > -1) return false;
      if (excludeAmbiguous && AMBIGUOUS.indexOf(ch) > -1) return false;
      return true;
    }).join('');
  }

  // Build the list of enabled, filtered sets from current settings.
  function buildSets(s) {
    var active = [];
    if (s.upper)  active.push(filterSet(SETS.upper,  s.similar, s.ambig));
    if (s.lower)  active.push(filterSet(SETS.lower,  s.similar, s.ambig));
    if (s.number) active.push(filterSet(SETS.number, s.similar, s.ambig));
    if (s.symbol) active.push(filterSet(SYMBOL_FULL, s.similar, s.ambig));
    // Drop any set that ended up empty after filtering.
    return active.filter(function (set) { return set.length > 0; });
  }

  /* ------------------------------------------------------------------ *
   * Generators
   * ------------------------------------------------------------------ */

  // Returns { value, poolSize } or throws if no sets are active.
  function generatePassword(s) {
    var sets = buildSets(s);
    if (sets.length === 0) throw new Error('No character sets selected.');

    var pool = sets.join('');
    var poolSize = pool.length;
    var length = WUS.clamp(parseInt(s.length, 10) || 20, 4, 64);

    var chars = [];

    // Guarantee at least one character from each enabled set (when length allows).
    var guaranteed = Math.min(sets.length, length);
    for (var k = 0; k < guaranteed; k++) chars.push(pick(sets[k]));

    // Fill the rest from the combined pool.
    for (var n = chars.length; n < length; n++) chars.push(pick(pool));

    // Securely shuffle so guaranteed chars aren't front-loaded.
    secureShuffle(chars);

    return { value: chars.join(''), poolSize: poolSize };
  }

  // Passphrase: N random words + separator, optional capitalization & number.
  function generatePassphrase(s) {
    var count = WUS.clamp(parseInt(s.words, 10) || 4, 3, 8);
    var words = [];
    for (var i = 0; i < count; i++) {
      var w = WORDLIST[randomInt(WORDLIST.length)];
      if (s.capitalize) w = w.charAt(0).toUpperCase() + w.slice(1);
      words.push(w);
    }
    var sep = (typeof s.separator === 'string') ? s.separator : '-';
    var phrase = words.join(sep);
    if (s.ppNumber) {
      var num = randomInt(100); // 0..99
      phrase += sep + (num < 10 ? '0' + num : '' + num);
    }
    // Entropy of a passphrase is driven by the word-selection space, not the
    // character pool, so we report the effective word-list size as "pool".
    return { value: phrase, poolSize: WORDLIST.length, words: count, hasNumber: !!s.ppNumber };
  }

  /* ------------------------------------------------------------------ *
   * Entropy & strength analysis
   * ------------------------------------------------------------------ */

  // bits = length * log2(poolSize) for char passwords;
  // for passphrases: words*log2(listSize) (+ ~6.6 bits for a 2-digit number).
  function computeEntropy(mode, result, s) {
    if (mode === 'passphrase') {
      var bits = result.words * Math.log2(result.poolSize);
      if (result.hasNumber) bits += Math.log2(100);
      return bits;
    }
    return result.value.length * Math.log2(result.poolSize);
  }

  function strengthFromEntropy(bits) {
    if (bits < 36) return STRENGTH[1];
    if (bits < 60) return STRENGTH[2];
    if (bits < 80) return STRENGTH[3];
    if (bits < 112) return STRENGTH[4];
    return STRENGTH[5];
  }

  // Human-readable crack time. Average guesses = 2^bits / 2.
  function crackTime(bits) {
    // Work in log10 seconds to avoid Infinity for huge entropies.
    var log10Guesses = (bits - 1) * Math.log10(2);           // 2^(bits-1)
    var log10Seconds = log10Guesses - Math.log10(GUESSES_PER_SEC);
    if (log10Seconds < -3) return 'instantly';

    var seconds = Math.pow(10, log10Seconds);
    var units = [
      ['century',     60 * 60 * 24 * 365 * 100],
      ['year',        60 * 60 * 24 * 365],
      ['month',       60 * 60 * 24 * 30],
      ['day',         60 * 60 * 24],
      ['hour',        60 * 60],
      ['minute',      60],
      ['second',      1],
      ['millisecond', 0.001]
    ];

    // If beyond the largest unit, express in centuries (with magnitude).
    if (seconds >= units[0][1]) {
      var centuries = seconds / units[0][1];
      if (log10Seconds - Math.log10(units[0][1]) > 6) {
        // Astronomically large — show order of magnitude.
        var exp = Math.floor(Math.log10(centuries));
        return '10^' + exp + ' centuries';
      }
      return formatCount(centuries, 'century', 'centuries');
    }

    for (var i = 0; i < units.length; i++) {
      if (seconds >= units[i][1]) {
        var amount = seconds / units[i][1];
        return formatCount(amount, units[i][0], units[i][0] + 's');
      }
    }
    return 'instantly';
  }

  function formatCount(amount, singular, plural) {
    var rounded = amount >= 10 ? Math.round(amount) : Math.round(amount * 10) / 10;
    var label = rounded === 1 ? singular : plural;
    // Add thousands separators for big readable numbers.
    var num = rounded >= 1000 ? Math.round(rounded).toLocaleString() : rounded;
    return num + ' ' + label;
  }

  /* ------------------------------------------------------------------ *
   * DOM references
   * ------------------------------------------------------------------ */
  var $ = function (id) { return document.getElementById(id); };

  var ui = {
    output: $('output'),
    poolBadge: $('pool-badge'),
    copyBtn: $('copy-btn'),
    regenBtn: $('regen-btn'),
    // mode
    modePassword: $('mode-password'),
    modePassphrase: $('mode-passphrase'),
    passwordOptions: $('password-options'),
    passphraseOptions: $('passphrase-options'),
    inlineHint: $('inline-hint'),
    // password opts
    length: $('length'),
    lengthReadout: $('length-readout'),
    optUpper: $('opt-upper'),
    optLower: $('opt-lower'),
    optNumber: $('opt-number'),
    optSymbol: $('opt-symbol'),
    optSimilar: $('opt-similar'),
    optAmbig: $('opt-ambig'),
    // passphrase opts
    words: $('words'),
    wordsReadout: $('words-readout'),
    separator: $('separator'),
    optCapitalize: $('opt-capitalize'),
    optPpNumber: $('opt-pp-number'),
    // strength
    meter: $('meter'),
    strengthLabel: $('strength-label'),
    entropyReadout: $('entropy-readout'),
    statEntropy: $('stat-entropy'),
    statPool: $('stat-pool'),
    statLength: $('stat-length'),
    statCrack: $('stat-crack'),
    // history
    historyList: $('history-list'),
    historyEmpty: $('history-empty'),
    clearHistory: $('clear-history'),
    // help
    helpModal: $('help-modal'),
    helpClose: $('help-close')
  };

  /* ------------------------------------------------------------------ *
   * State
   * ------------------------------------------------------------------ */
  var state = {
    mode: 'password',     // 'password' | 'passphrase'
    current: '',          // current generated value
    history: []
  };

  function readSettings() {
    return {
      mode: state.mode,
      length: parseInt(ui.length.value, 10),
      upper: ui.optUpper.checked,
      lower: ui.optLower.checked,
      number: ui.optNumber.checked,
      symbol: ui.optSymbol.checked,
      similar: ui.optSimilar.checked,
      ambig: ui.optAmbig.checked,
      words: parseInt(ui.words.value, 10),
      separator: ui.separator.value,
      capitalize: ui.optCapitalize.checked,
      ppNumber: ui.optPpNumber.checked
    };
  }

  function persistSettings() {
    WUS.store.set(SETTINGS_KEY, readSettings());
  }

  function restoreSettings() {
    var s = WUS.store.get(SETTINGS_KEY, null);
    if (!s) return;
    try {
      if (s.mode === 'passphrase' || s.mode === 'password') state.mode = s.mode;
      if (typeof s.length === 'number') ui.length.value = WUS.clamp(s.length, 4, 64);
      if (typeof s.upper === 'boolean') ui.optUpper.checked = s.upper;
      if (typeof s.lower === 'boolean') ui.optLower.checked = s.lower;
      if (typeof s.number === 'boolean') ui.optNumber.checked = s.number;
      if (typeof s.symbol === 'boolean') ui.optSymbol.checked = s.symbol;
      if (typeof s.similar === 'boolean') ui.optSimilar.checked = s.similar;
      if (typeof s.ambig === 'boolean') ui.optAmbig.checked = s.ambig;
      if (typeof s.words === 'number') ui.words.value = WUS.clamp(s.words, 3, 8);
      if (typeof s.separator === 'string') ui.separator.value = s.separator;
      if (typeof s.capitalize === 'boolean') ui.optCapitalize.checked = s.capitalize;
      if (typeof s.ppNumber === 'boolean') ui.optPpNumber.checked = s.ppNumber;
    } catch (e) { /* ignore corrupt settings */ }
  }

  /* ------------------------------------------------------------------ *
   * Rendering
   * ------------------------------------------------------------------ */

  // Render the output with subtle per-char coloring (numbers / symbols).
  function renderOutput(value) {
    var html = value.split('').map(function (ch) {
      var safe = WUS.escapeHtml(ch);
      if (/[0-9]/.test(ch)) return '<span class="c-num">' + safe + '</span>';
      if (/[^A-Za-z0-9]/.test(ch)) return '<span class="c-sym">' + safe + '</span>';
      return safe;
    }).join('');
    ui.output.innerHTML = html;
    // retrigger reveal animation
    ui.output.classList.remove('--pop');
    void ui.output.offsetWidth; // force reflow
    ui.output.classList.add('--pop');
  }

  function renderStrength(bits, poolSize, length) {
    var info = strengthFromEntropy(bits);
    var bitsRounded = Math.round(bits);

    // meter
    ui.meter.className = 'meter lvl-' + info.lvl;
    // label
    ui.strengthLabel.textContent = info.label;
    ui.strengthLabel.className = 'strength-label lbl-' + info.lvl;
    // readouts
    ui.entropyReadout.textContent = bitsRounded + ' bits';
    ui.statEntropy.textContent = bitsRounded + ' bits';
    ui.statPool.textContent = poolSize;
    ui.statLength.textContent = length;
    ui.statCrack.textContent = crackTime(bits);
  }

  function updatePoolBadge() {
    try {
      if (state.mode === 'passphrase') {
        ui.poolBadge.textContent = WORDLIST.length + '-word list';
      } else {
        var sets = buildSets(readSettings());
        var size = sets.join('').length;
        ui.poolBadge.textContent = size + ' characters';
      }
    } catch (e) {
      ui.poolBadge.textContent = '— characters';
    }
  }

  // Enable/disable Generate when no character sets are active (password mode).
  function refreshGenerateAvailability() {
    var canGenerate = true;
    if (state.mode === 'password') {
      var sets = buildSets(readSettings());
      canGenerate = sets.length > 0;
    }
    ui.regenBtn.disabled = !canGenerate;
    ui.copyBtn.disabled = !canGenerate && !state.current;
    ui.inlineHint.hidden = canGenerate || state.mode !== 'password';
    return canGenerate;
  }

  /* ------------------------------------------------------------------ *
   * Generation flow
   * ------------------------------------------------------------------ */

  function generate(addToHistory) {
    try {
      var s = readSettings();
      var result;

      if (state.mode === 'passphrase') {
        result = generatePassphrase(s);
      } else {
        if (buildSets(s).length === 0) {
          refreshGenerateAvailability();
          WUS.toast('Select at least one character set.', 'error');
          return;
        }
        result = generatePassword(s);
      }

      var bits = computeEntropy(state.mode, result, s);
      state.current = result.value;

      renderOutput(result.value);
      renderStrength(bits, result.poolSize, result.value.length);
      ui.copyBtn.disabled = false;

      if (addToHistory) pushHistory(result.value, bits);
    } catch (err) {
      WUS.toast(err.message || 'Generation failed.', 'error');
    }
  }

  function copyCurrent() {
    if (!state.current) { WUS.toast('Nothing to copy yet.', 'error'); return; }
    WUS.copy(state.current, 'Password copied to clipboard');
  }

  /* ------------------------------------------------------------------ *
   * History
   * ------------------------------------------------------------------ */

  function loadHistory() {
    var h = WUS.store.get(HISTORY_KEY, []);
    state.history = Array.isArray(h) ? h : [];
  }

  function saveHistory() {
    WUS.store.set(HISTORY_KEY, state.history);
  }

  function pushHistory(value, bits) {
    state.history.unshift({
      id: WUS.uid(),
      value: value,
      entropy: Math.round(bits),
      mode: state.mode,
      ts: Date.now()
    });
    if (state.history.length > MAX_HISTORY) state.history.length = MAX_HISTORY;
    saveHistory();
    renderHistory();
  }

  function deleteHistory(id) {
    state.history = state.history.filter(function (item) { return item.id !== id; });
    saveHistory();
    renderHistory();
  }

  function clearHistory() {
    if (state.history.length === 0) return;
    state.history = [];
    saveHistory();
    renderHistory();
    WUS.toast('History cleared');
  }

  function maskValue(value) {
    if (value.length <= 4) return '•'.repeat(value.length);
    return value.slice(0, 2) + '•'.repeat(Math.max(4, value.length - 4)) + value.slice(-2);
  }

  function renderHistory() {
    ui.historyList.innerHTML = '';
    var has = state.history.length > 0;
    ui.historyEmpty.hidden = has;
    ui.clearHistory.hidden = !has;

    state.history.forEach(function (item) {
      var li = WUS.el('li', { class: 'history-item' });

      var main = WUS.el('div', { class: 'hi-main' });
      var value = WUS.el('div', { class: 'hi-value', text: maskValue(item.value) });
      value.dataset.revealed = 'false';

      var meta = WUS.el('div', { class: 'hi-meta' }, [
        WUS.el('span', { text: item.entropy + ' bits' }),
        WUS.el('span', { class: 'dot-sep', text: '·' }),
        WUS.el('span', { text: item.mode === 'passphrase' ? 'passphrase' : 'password' }),
        WUS.el('span', { class: 'dot-sep', text: '·' }),
        WUS.el('span', { text: WUS.formatDate(item.ts) })
      ]);

      main.appendChild(value);
      main.appendChild(meta);

      // actions: peek / copy / delete
      var actions = WUS.el('div', { class: 'hi-actions' });

      var peekBtn = WUS.el('button', {
        class: 'hi-btn', type: 'button',
        'aria-label': 'Reveal password', title: 'Reveal',
        html: eyeIcon(false)
      });
      peekBtn.addEventListener('click', function () {
        var revealed = value.dataset.revealed === 'true';
        if (revealed) {
          value.textContent = maskValue(item.value);
          value.dataset.revealed = 'false';
          peekBtn.classList.remove('is-on');
          peekBtn.innerHTML = eyeIcon(false);
          peekBtn.setAttribute('aria-label', 'Reveal password');
          peekBtn.title = 'Reveal';
        } else {
          value.textContent = item.value;
          value.dataset.revealed = 'true';
          peekBtn.classList.add('is-on');
          peekBtn.innerHTML = eyeIcon(true);
          peekBtn.setAttribute('aria-label', 'Hide password');
          peekBtn.title = 'Hide';
        }
      });

      var copyBtn = WUS.el('button', {
        class: 'hi-btn', type: 'button',
        'aria-label': 'Copy password', title: 'Copy',
        html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>'
      });
      copyBtn.addEventListener('click', function () {
        WUS.copy(item.value, 'Password copied to clipboard');
      });

      var delBtn = WUS.el('button', {
        class: 'hi-btn danger', type: 'button',
        'aria-label': 'Delete from history', title: 'Delete',
        html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path><path d="M10 11v6M14 11v6"></path></svg>'
      });
      delBtn.addEventListener('click', function () { deleteHistory(item.id); });

      actions.appendChild(peekBtn);
      actions.appendChild(copyBtn);
      actions.appendChild(delBtn);

      li.appendChild(main);
      li.appendChild(actions);
      ui.historyList.appendChild(li);
    });
  }

  function eyeIcon(open) {
    if (open) {
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
    }
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><path d="M1 1l22 22"></path></svg>';
  }

  /* ------------------------------------------------------------------ *
   * Mode switching
   * ------------------------------------------------------------------ */
  function setMode(mode) {
    state.mode = mode;
    var isPass = mode === 'passphrase';

    ui.modePassword.setAttribute('aria-selected', String(!isPass));
    ui.modePassword.classList.toggle('is-active', !isPass);
    ui.modePassphrase.setAttribute('aria-selected', String(isPass));
    ui.modePassphrase.classList.toggle('is-active', isPass);

    ui.passwordOptions.hidden = isPass;
    ui.passphraseOptions.hidden = !isPass;

    updatePoolBadge();
    refreshGenerateAvailability();
    persistSettings();
    generate(false); // preview without polluting history
  }

  /* ------------------------------------------------------------------ *
   * Help modal
   * ------------------------------------------------------------------ */
  function openHelp() {
    ui.helpModal.hidden = false;
    ui.helpClose.focus();
  }
  function closeHelp() {
    ui.helpModal.hidden = true;
  }

  /* ------------------------------------------------------------------ *
   * Wiring
   * ------------------------------------------------------------------ */
  function onOptionChange() {
    updatePoolBadge();
    refreshGenerateAvailability();
    persistSettings();
  }

  function init() {
    restoreSettings();
    loadHistory();
    renderHistory();

    // sync readouts
    ui.lengthReadout.textContent = ui.length.value;
    ui.wordsReadout.textContent = ui.words.value;

    // Mode tabs
    ui.modePassword.addEventListener('click', function () { setMode('password'); });
    ui.modePassphrase.addEventListener('click', function () { setMode('passphrase'); });

    // Length slider (live readout + live regenerate preview)
    ui.length.addEventListener('input', function () {
      ui.lengthReadout.textContent = ui.length.value;
      onOptionChange();
      generate(false);
    });
    ui.words.addEventListener('input', function () {
      ui.wordsReadout.textContent = ui.words.value;
      onOptionChange();
      generate(false);
    });

    // Toggles & selects → live preview
    [ui.optUpper, ui.optLower, ui.optNumber, ui.optSymbol, ui.optSimilar, ui.optAmbig]
      .forEach(function (input) {
        input.addEventListener('change', function () {
          onOptionChange();
          if (refreshGenerateAvailability()) generate(false);
        });
      });
    [ui.separator, ui.optCapitalize, ui.optPpNumber].forEach(function (input) {
      input.addEventListener('change', function () {
        onOptionChange();
        generate(false);
      });
    });

    // Buttons
    ui.copyBtn.addEventListener('click', copyCurrent);
    ui.regenBtn.addEventListener('click', function () { generate(true); });
    ui.clearHistory.addEventListener('click', clearHistory);

    // Help modal
    document.querySelectorAll('[data-shortcut-help]').forEach(function (b) {
      b.addEventListener('click', openHelp);
    });
    ui.helpClose.addEventListener('click', closeHelp);
    ui.helpModal.addEventListener('click', function (e) {
      if (e.target === ui.helpModal) closeHelp();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !ui.helpModal.hidden) closeHelp();
    });

    // Shortcuts (core.js ignores bare keys while typing in inputs)
    WUS.registerShortcut('space', function () { generate(true); }, 'Generate a new password');
    WUS.registerShortcut('enter', function () { generate(true); }, 'Generate a new password');
    WUS.registerShortcut('mod+c', function () {
      // Don't hijack copy when the user has an active text selection.
      var sel = window.getSelection && window.getSelection().toString();
      if (sel && sel.length) return;
      copyCurrent();
    }, 'Copy current password');
    WUS.registerShortcut('?', openHelp, 'Show keyboard shortcuts');

    // First render
    updatePoolBadge();
    refreshGenerateAvailability();
    generate(true); // initial password counts as the first history entry
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
