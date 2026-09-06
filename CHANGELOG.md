# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.1] - 2026-09-06

### Fixed

- Fixed double-encoded UTF-8 text ("mojibake") in `index.html` that rendered as garbled characters (e.g. `â€"`, `Â·`, `âŒ˜`) instead of the intended em dashes, en dashes, ellipsis, middle dot, and the `⌘` symbol. Affected the page `<title>`, meta description, hero copy, the pool-size badge placeholder, strength/crack-time placeholders, the character-range hints (`A–Z`, `a–z`, `0–9`, `!@#$…`), the footer, and the keyboard-shortcuts modal.
