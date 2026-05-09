# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-09

### Added

- Initial public release.
- Rust core crate `maskprompt-core`.
- Built-in detectors: email, US phone, IPv4, IPv6, US Social Security Number,
  AWS access key (AKIA*), GitHub PAT (ghp_/gho_/ghu_/ghr_/ghs_), JWT,
  credit card with Luhn validation.
- Aho-Corasick custom keyword sets, multiple labels per `Masker`.
- Four redaction strategies: `Tag` (`<EMAIL>`), `Hash` (`<EMAIL:abc12345>`,
  blake3-truncated for stable cross-run redaction), `Fixed` (`█` repeat),
  `Remove` (empty string).
- Python package `maskprompt` with the same API and a `MaskResult` dataclass.
- abi3-py310 wheel: one wheel for CPython 3.10 through 3.13.

[Unreleased]: https://github.com/MukundaKatta/maskprompt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MukundaKatta/maskprompt/releases/tag/v0.1.0
