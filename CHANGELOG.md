# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.2] - 2026-09-06

### Fixed

- Fixed the History panel's masked value for short generated passwords
  (lengths 5-7, reachable via the length slider's 4-64 range): `maskValue`
  sliced off the first and last two characters and padded the middle with a
  *minimum* of 4 dots, which for a 5-character value left only 1 real
  character actually hidden behind those dots — the other 4 (80%) were
  shown in plain text before the user ever clicked "Reveal". Values shorter
  than 8 characters are now fully masked instead; behavior for length 8+
  (where the head/tail reveal no longer dominates the string) is unchanged.

## [1.0.1] - 2026-09-06

### Fixed

- Fixed double-encoded UTF-8 text ("mojibake") in `index.html` that rendered as garbled characters (e.g. `â€"`, `Â·`, `âŒ˜`) instead of the intended em dashes, en dashes, ellipsis, middle dot, and the `⌘` symbol. Affected the page `<title>`, meta description, hero copy, the pool-size badge placeholder, strength/crack-time placeholders, the character-range hints (`A–Z`, `a–z`, `0–9`, `!@#$…`), the footer, and the keyboard-shortcuts modal.
