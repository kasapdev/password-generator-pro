# Password Generator Pro

[![CI](https://github.com/kasapdev/password-generator-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/kasapdev/password-generator-pro/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![Vanilla JS](https://img.shields.io/badge/Vanilla-JS-F7DF1E?logo=javascript&logoColor=black)

Cryptographically-secure passwords and passphrases with live strength + entropy analysis.

> A polished, fully-offline password generator that uses `crypto.getRandomValues` (never `Math.random`), avoids modulo bias via rejection sampling, and shows real-time entropy, character-pool size, and a human-readable crack-time estimate. Part of the Web Utility Suite.

## Overview

Password Generator Pro creates strong, unpredictable secrets entirely in your browser. No data ever leaves the page — there are no servers, no network requests, and no analytics. Generate classic character passwords or memorable word-based passphrases, watch the strength meter react instantly, and keep a private history of your last 20 generations in local storage.

The generator is built for correctness as well as looks: every random choice comes from the Web Crypto API, the character pool is sampled with rejection sampling to eliminate modulo bias, at least one character from each enabled set is guaranteed, and the result is securely shuffled with Fisher–Yates so guaranteed characters are never front-loaded.

## Features

- **Cryptographically secure** — all randomness comes from `crypto.getRandomValues`; modulo bias is removed with rejection sampling.
- **Adjustable length** — slider from 4 to 64 characters (default 20) with a live numeric readout.
- **Character sets** — toggle Uppercase, Lowercase, Numbers, and Symbols independently.
- **Exclusion options** — exclude similar glyphs (`I l 1 O 0`) and ambiguous punctuation (`{ } [ ] ( ) / \\ …`).
- **Guaranteed coverage** — at least one character from every enabled set, then a secure shuffle.
- **Passphrase mode** — 3–8 random words from a built-in word list, choice of separator, optional capitalization and an appended random number.
- **Live strength analysis** — segmented colored meter with Very weak → Excellent labels.
- **Entropy & crack time** — entropy in bits (`length × log₂(poolSize)`), pool size, and a crack-time estimate assuming 10 billion guesses/sec, formatted from "instantly" up to centuries.
- **History** — last 20 results stored locally, each with masked value + peek toggle, copy, and delete, plus Clear all. Newest first, with a friendly empty state.
- **One-click copy & regenerate** — with a subtle reveal animation on each generation.
- **Persistent settings** — your options are remembered between visits.
- **Dark & light themes** — instant toggle, system-aware by default.
- **Fully responsive** — designed mobile-first, comfortable down to 360px.
- **Accessible** — semantic markup, labelled controls, ARIA live regions, keyboard operable, visible focus.
- **100% offline** — open `index.html` straight from disk; no build step, no dependencies.

## Installation

No dependencies and no build step.

```bash
git clone https://github.com/your-org/web-utility-suite.git
cd web-utility-suite/password-generator
```

Then simply open `index.html` in any modern browser (it works directly from the file system via `file://`), or open it from the Web Utility Suite landing page.

## Usage

1. Choose **Password** or **Passphrase** from the segmented control.
2. In **Password** mode, drag the length slider and toggle the character sets and exclusion options you want. In **Passphrase** mode, pick the number of words, a separator, and whether to capitalize words or append a number.
3. The result, strength meter, and entropy stats update live as you change options.
4. Press **Regenerate** (or hit `Space` / `Enter`) for a fresh value.
5. Click **Copy** (or `Ctrl/⌘ + C`) to copy the current password.
6. Review the **History** panel to re-copy, reveal, or delete previous results, or **Clear all** at once.

## Keyboard Shortcuts

| Action | Shortcut |
| --- | --- |
| Generate a new password | `Space` or `Enter` |
| Copy current password | `Ctrl/⌘ + C` |
| Open shortcuts help | `?` |
| Close dialog | `Esc` |

> Bare-key shortcuts are automatically ignored while you are typing in an input or select, so they never interfere with form controls.

## Screenshots

> _Screenshots coming soon._

![screenshot](docs/screenshot-1.png)
![screenshot](docs/screenshot-2.png)

## Roadmap

- [ ] Bulk generation (export N passwords as CSV / TXT)
- [ ] Optional pronounceable-password mode
- [ ] Configurable minimum counts per character class
- [ ] Have-I-Been-Pwned k-anonymity check (opt-in, online)
- [ ] PIN mode for numeric-only secrets

## License

MIT Licensed. Part of the [Web Utility Suite](../index.html).

---

## Part of the kasapdev Tools Suite

One of 45+ zero-dependency vanilla JS tools, all free and open source — [see the full list](https://github.com/kasapdev/kasapdev).
