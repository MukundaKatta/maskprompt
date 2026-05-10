//! Pure-Rust core for `maskprompt`. Detects common PII patterns plus
//! caller-supplied keywords and replaces them via one of four strategies.
//!
//! - **Built-in rules.** A small fixed set of regex patterns. Credit-card
//!   matches are validated through Luhn before redaction so unrelated
//!   13–19 digit strings (order numbers, etc.) are not flagged.
//! - **Custom keywords.** An Aho-Corasick automaton over the union of all
//!   user-supplied needles, so a list with thousands of entries (customer
//!   names, internal project codes) still matches in linear time.
//! - **Strategies.** `Tag`, `Hash`, `Fixed`, `Remove`. The `Hash` strategy
//!   uses blake3 truncated to 8 hex chars to give stable cross-run
//!   redaction without recovering the source.
//!
//! Match resolution: when two rules overlap, the one that started earlier
//! wins; ties go to the longer match.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, MaskerError>;

/// All errors surfaced by `maskprompt-core`.
#[derive(Error, Debug)]
pub enum MaskerError {
    /// Caller supplied an invalid configuration.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// A regex failed to compile. Should not happen at runtime; built-in
    /// patterns are tested. Surfaces if a future caller adds custom regex.
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    /// Aho-Corasick build failure.
    #[error("aho-corasick error: {0}")]
    Aho(#[from] aho_corasick::BuildError),
}

/// Built-in detector identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinRule {
    /// Email addresses (RFC-5322-ish).
    Email,
    /// US phone numbers in the most common formats.
    UsPhone,
    /// US Social Security Numbers (`XXX-XX-XXXX`).
    UsSsn,
    /// IPv4 dotted-quad addresses.
    Ipv4,
    /// IPv6 addresses including `::` shorthand.
    Ipv6,
    /// 13-19 digit candidates that pass Luhn validation.
    CreditCard,
    /// AWS access key IDs (`AKIA…` + 16 alphanumerics).
    AwsAccessKey,
    /// GitHub personal access tokens / OAuth tokens.
    GithubToken,
    /// JWTs (three base64url segments separated by `.`).
    Jwt,
    /// HTTP/HTTPS URLs.
    Url,
    /// MAC addresses in colon or dash form (`AA:BB:CC:DD:EE:FF`).
    MacAddress,
    /// IBAN bank account numbers. Matches the standard 2-letter country
    /// code + 2 check digits + up to 30 alphanumerics.
    Iban,
}

impl BuiltinRule {
    /// Stable lowercase tag used as `<TAG>` and as the key in [`MaskMatch::kind`].
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::UsPhone => "US_PHONE",
            Self::UsSsn => "US_SSN",
            Self::Ipv4 => "IPV4",
            Self::Ipv6 => "IPV6",
            Self::CreditCard => "CREDIT_CARD",
            Self::AwsAccessKey => "AWS_ACCESS_KEY",
            Self::GithubToken => "GITHUB_TOKEN",
            Self::Jwt => "JWT",
            Self::Url => "URL",
            Self::MacAddress => "MAC_ADDRESS",
            Self::Iban => "IBAN",
        }
    }

    fn pattern(&self) -> &'static str {
        match self {
            // Conservative email pattern: no unicode escapes, no quoted local
            // parts. Covers the >99% case in production logs.
            Self::Email => r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b",
            Self::UsPhone => {
                r"(?x)
                    \b
                    (?:\+?1[-.\ ]?)?
                    (?:\(\d{3}\)|\d{3})[-.\ ]?
                    \d{3}[-.\ ]?
                    \d{4}
                    \b
                "
            }
            Self::UsSsn => r"\b\d{3}-\d{2}-\d{4}\b",
            Self::Ipv4 => {
                r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
            }
            // IPv6: simplified. Covers full and `::`-shorthand forms; will
            // false-positive on a few invalid strings (we don't validate hex
            // group counts strictly) but those are rare in production logs.
            Self::Ipv6 => {
                r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|::(?:[0-9a-fA-F]{1,4}:?){1,7}\b"
            }
            // Credit card: 13-19 digits, optional dash/space separators every 4.
            // Luhn validation runs after the regex match.
            Self::CreditCard => r"\b(?:\d[\ -]?){12,18}\d\b",
            Self::AwsAccessKey => r"\bAKIA[0-9A-Z]{16}\b",
            // GitHub token formats: ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server),
            // ghr_ (refresh), ghs_ (server-to-server).
            Self::GithubToken => r"\bgh[pours]_[A-Za-z0-9]{36,}\b",
            // JWT: three url-safe base64 segments. Allows long signatures.
            Self::Jwt => r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            // URLs: http(s) + host + optional path. Conservative; doesn't
            // try to catch unicode-heavy IDN forms.
            Self::Url => {
                r"https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
            }
            // MAC addresses in 6-group colon or dash notation.
            Self::MacAddress => r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            // IBAN: 2 letters + 2 digits + 11–30 alphanumerics. Length cap
            // matches the longest IBAN spec (Malta = 31 chars total).
            Self::Iban => r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        }
    }

    /// Return all built-in rules in declaration order.
    pub fn all() -> [BuiltinRule; 12] {
        [
            Self::Email,
            Self::UsPhone,
            Self::UsSsn,
            Self::Ipv4,
            Self::Ipv6,
            Self::CreditCard,
            Self::AwsAccessKey,
            Self::GithubToken,
            Self::Jwt,
            Self::Url,
            Self::MacAddress,
            Self::Iban,
        ]
    }
}

/// How matches are replaced in the masked string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Replace with `<TAG>` (e.g. `<EMAIL>`). Default.
    #[default]
    Tag,
    /// Replace with `<TAG:abc12345>` where the suffix is blake3 of the
    /// original value, truncated to 8 hex characters. Stable across runs.
    Hash,
    /// Replace with `█` repeated, preserving the original length.
    Fixed,
    /// Replace with the empty string.
    Remove,
    /// Keep the first `prefix` characters of the original value, then
    /// append `…<TAG>`. Useful when the prefix carries debugging signal
    /// (e.g. `4111…<CREDIT_CARD>` for the BIN of a card number).
    Truncate(u8),
}

/// One match found by [`Masker::mask`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskMatch {
    /// Lowercase tag (built-in rules return their `tag()`, custom rules
    /// return the user-provided label uppercased).
    pub kind: String,
    /// Byte-offset of the match start in the original string.
    pub start: usize,
    /// Byte-offset of the match end in the original string (exclusive).
    pub end: usize,
    /// The matched substring (preserved so the caller can hash, log, etc.).
    pub value: String,
}

/// Output of [`Masker::mask`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskResult {
    /// The redacted string.
    pub masked: String,
    /// One entry per redaction, in left-to-right order.
    pub matches: Vec<MaskMatch>,
}

/// Compiled detector set. Build with [`Masker::builder`].
pub struct Masker {
    builtin: Vec<(BuiltinRule, Regex)>,
    keywords: Vec<KeywordSet>,
}

struct KeywordSet {
    label: String,
    automaton: AhoCorasick,
}

impl Masker {
    /// Start a new builder.
    pub fn builder() -> MaskerBuilder {
        MaskerBuilder::default()
    }

    /// Convenience: a Masker with every built-in rule and no custom keywords.
    pub fn with_all_builtins() -> Result<Self> {
        let mut b = Self::builder();
        for r in BuiltinRule::all() {
            b = b.with_builtin(r);
        }
        b.build()
    }

    /// Run all detectors against `text` and apply `strategy` to every match.
    pub fn mask(&self, text: &str, strategy: Strategy) -> MaskResult {
        let mut spans: Vec<MaskMatch> = Vec::new();

        // Built-in detectors.
        for (rule, regex) in &self.builtin {
            for m in regex.find_iter(text) {
                let value = &text[m.start()..m.end()];
                if *rule == BuiltinRule::CreditCard && !is_luhn_valid(value) {
                    continue;
                }
                spans.push(MaskMatch {
                    kind: rule.tag().to_string(),
                    start: m.start(),
                    end: m.end(),
                    value: value.to_string(),
                });
            }
        }

        // Custom keyword sets.
        for set in &self.keywords {
            for m in set.automaton.find_iter(text) {
                spans.push(MaskMatch {
                    kind: set.label.clone(),
                    start: m.start(),
                    end: m.end(),
                    value: text[m.start()..m.end()].to_string(),
                });
            }
        }

        // Resolve overlaps: earliest start wins; ties broken by longer span.
        spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut kept: Vec<MaskMatch> = Vec::with_capacity(spans.len());
        let mut cursor = 0usize;
        for m in spans {
            if m.start < cursor {
                continue;
            }
            cursor = m.end;
            kept.push(m);
        }

        // Build the masked string.
        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        for m in &kept {
            out.push_str(&text[last..m.start]);
            out.push_str(&render(&m.kind, &m.value, strategy));
            last = m.end;
        }
        out.push_str(&text[last..]);
        MaskResult {
            masked: out,
            matches: kept,
        }
    }
}

/// Builder for [`Masker`].
#[derive(Default)]
pub struct MaskerBuilder {
    builtins: Vec<BuiltinRule>,
    keywords: Vec<(String, Vec<String>)>,
}

impl MaskerBuilder {
    /// Enable a built-in detector. Calling twice is idempotent.
    pub fn with_builtin(mut self, rule: BuiltinRule) -> Self {
        if !self.builtins.contains(&rule) {
            self.builtins.push(rule);
        }
        self
    }

    /// Register a custom keyword set under `label`. Matching is
    /// case-insensitive. Empty needles are silently dropped.
    pub fn with_keywords<S: Into<String>>(mut self, label: S, needles: &[&str]) -> Self {
        let label = label.into().to_uppercase();
        let needles: Vec<String> = needles
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_string())
            .collect();
        self.keywords.push((label, needles));
        self
    }

    /// Build the [`Masker`].
    pub fn build(self) -> Result<Masker> {
        if self.builtins.is_empty() && self.keywords.iter().all(|(_, n)| n.is_empty()) {
            return Err(MaskerError::InvalidConfig(
                "Masker has no rules; add at least one built-in or keyword set".into(),
            ));
        }
        let mut builtin = Vec::with_capacity(self.builtins.len());
        for r in self.builtins {
            let re = Regex::new(r.pattern())?;
            builtin.push((r, re));
        }
        let mut keywords = Vec::with_capacity(self.keywords.len());
        for (label, needles) in self.keywords {
            if needles.is_empty() {
                continue;
            }
            let automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(&needles)?;
            keywords.push(KeywordSet { label, automaton });
        }
        Ok(Masker { builtin, keywords })
    }
}

fn render(kind: &str, value: &str, strategy: Strategy) -> String {
    match strategy {
        Strategy::Tag => format!("<{kind}>"),
        Strategy::Hash => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(value.as_bytes());
            let h = hasher.finalize();
            let hex = h.to_hex();
            format!("<{kind}:{}>", &hex[..8])
        }
        Strategy::Fixed => "█".repeat(value.chars().count()),
        Strategy::Remove => String::new(),
        Strategy::Truncate(prefix) => {
            let prefix = prefix as usize;
            let kept: String = value.chars().take(prefix).collect();
            if kept.chars().count() == value.chars().count() {
                // Whole value fit — no truncation needed; treat as Tag so we
                // don't leak a value that was supposedly truncated.
                format!("<{kind}>")
            } else {
                format!("{kept}…<{kind}>")
            }
        }
    }
}

/// Luhn validation for credit-card numbers. Strips spaces and dashes first.
fn is_luhn_valid(s: &str) -> bool {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut x = d as u32;
        if alt {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        alt = !alt;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email_masker() -> Masker {
        Masker::builder()
            .with_builtin(BuiltinRule::Email)
            .build()
            .unwrap()
    }

    #[test]
    fn detects_email() {
        let m = email_masker();
        let r = m.mask("hi alice@example.com bye", Strategy::Tag);
        assert_eq!(r.masked, "hi <EMAIL> bye");
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].kind, "EMAIL");
        assert_eq!(r.matches[0].value, "alice@example.com");
    }

    #[test]
    fn no_match_returns_input_unchanged() {
        let m = email_masker();
        let r = m.mask("nothing here", Strategy::Tag);
        assert_eq!(r.masked, "nothing here");
        assert!(r.matches.is_empty());
    }

    #[test]
    fn luhn_valid_card_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::CreditCard)
            .build()
            .unwrap();
        // Real Visa test number, passes Luhn.
        let r = m.mask("paid 4111-1111-1111-1111 today", Strategy::Tag);
        assert_eq!(r.masked, "paid <CREDIT_CARD> today");
    }

    #[test]
    fn luhn_invalid_passes_through() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::CreditCard)
            .build()
            .unwrap();
        // 16 digits but doesn't pass Luhn.
        let r = m.mask("order 1234-5678-1234-5678", Strategy::Tag);
        assert_eq!(r.masked, "order 1234-5678-1234-5678");
        assert!(r.matches.is_empty());
    }

    #[test]
    fn ssn_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::UsSsn)
            .build()
            .unwrap();
        let r = m.mask("ssn 123-45-6789 ok", Strategy::Tag);
        assert_eq!(r.masked, "ssn <US_SSN> ok");
    }

    #[test]
    fn ipv4_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::Ipv4)
            .build()
            .unwrap();
        let r = m.mask("client 192.168.1.42", Strategy::Tag);
        assert_eq!(r.masked, "client <IPV4>");
    }

    #[test]
    fn aws_key_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::AwsAccessKey)
            .build()
            .unwrap();
        let r = m.mask("key AKIAIOSFODNN7EXAMPLE leaked", Strategy::Tag);
        assert_eq!(r.masked, "key <AWS_ACCESS_KEY> leaked");
    }

    #[test]
    fn github_token_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::GithubToken)
            .build()
            .unwrap();
        let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let r = m.mask(&format!("token {token} bad"), Strategy::Tag);
        assert_eq!(r.masked, "token <GITHUB_TOKEN> bad");
    }

    #[test]
    fn jwt_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::Jwt)
            .build()
            .unwrap();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.signature_part_long_enough";
        let r = m.mask(&format!("auth: {jwt} ok"), Strategy::Tag);
        assert_eq!(r.masked, "auth: <JWT> ok");
    }

    #[test]
    fn url_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::Url)
            .build()
            .unwrap();
        let r = m.mask("see https://example.com/path?x=1", Strategy::Tag);
        assert_eq!(r.masked, "see <URL>");
    }

    #[test]
    fn mac_address_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::MacAddress)
            .build()
            .unwrap();
        let r = m.mask("eth0 AA:BB:CC:DD:EE:FF up", Strategy::Tag);
        assert_eq!(r.masked, "eth0 <MAC_ADDRESS> up");
    }

    #[test]
    fn iban_redacted() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::Iban)
            .build()
            .unwrap();
        // Real IBAN test value (Germany).
        let r = m.mask("from DE89370400440532013000 today", Strategy::Tag);
        assert_eq!(r.masked, "from <IBAN> today");
    }

    #[test]
    fn truncate_strategy_keeps_prefix_and_appends_tag() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::CreditCard)
            .build()
            .unwrap();
        // BIN-style preservation: keep first 4 digits.
        let r = m.mask("paid 4111-1111-1111-1111 today", Strategy::Truncate(4));
        assert_eq!(r.masked, "paid 4111…<CREDIT_CARD> today");
    }

    #[test]
    fn truncate_strategy_short_value_falls_back_to_tag() {
        let m = email_masker();
        // Value is "a@b.com" (7 chars). Truncate(20) wouldn't actually
        // truncate, so it falls back to <TAG> rather than leaking the value.
        let r = m.mask("hi a@b.com", Strategy::Truncate(20));
        assert_eq!(r.masked, "hi <EMAIL>");
    }

    #[test]
    fn all_returns_twelve_rules() {
        assert_eq!(BuiltinRule::all().len(), 12);
    }

    #[test]
    fn keywords_redacted_case_insensitive() {
        let m = Masker::builder()
            .with_keywords("customer", &["Acme Corp", "Globex"])
            .build()
            .unwrap();
        let r = m.mask("call ACME corp and globex tomorrow", Strategy::Tag);
        assert_eq!(r.masked, "call <CUSTOMER> and <CUSTOMER> tomorrow");
        assert_eq!(r.matches.len(), 2);
    }

    #[test]
    fn multiple_rules_resolved_left_to_right() {
        let m = Masker::builder()
            .with_builtin(BuiltinRule::Email)
            .with_builtin(BuiltinRule::CreditCard)
            .build()
            .unwrap();
        let text = "email alice@example.com card 4111-1111-1111-1111 done";
        let r = m.mask(text, Strategy::Tag);
        assert_eq!(r.masked, "email <EMAIL> card <CREDIT_CARD> done");
        assert_eq!(r.matches.len(), 2);
        assert!(r.matches[0].start < r.matches[1].start);
    }

    #[test]
    fn hash_strategy_is_stable_for_same_value() {
        let m = email_masker();
        let r1 = m.mask("a@b.com", Strategy::Hash);
        let r2 = m.mask("a@b.com", Strategy::Hash);
        assert_eq!(r1.masked, r2.masked);
        let r3 = m.mask("c@d.com", Strategy::Hash);
        assert_ne!(r1.masked, r3.masked);
    }

    #[test]
    fn hash_strategy_format() {
        let m = email_masker();
        let r = m.mask("a@b.com", Strategy::Hash);
        // <EMAIL:xxxxxxxx>
        assert!(r.masked.starts_with("<EMAIL:"));
        assert!(r.masked.ends_with('>'));
        assert_eq!(r.masked.len(), "<EMAIL:".len() + 8 + 1);
    }

    #[test]
    fn fixed_strategy_preserves_length() {
        let m = email_masker();
        let r = m.mask("hi a@b.com bye", Strategy::Fixed);
        // a@b.com -> 7 chars -> 7 block characters (each block char is 3 bytes in UTF-8).
        assert!(r.masked.contains('█'));
        assert!(r.masked.starts_with("hi "));
        assert!(r.masked.ends_with(" bye"));
    }

    #[test]
    fn remove_strategy_strips_match() {
        let m = email_masker();
        let r = m.mask("hi a@b.com bye", Strategy::Remove);
        assert_eq!(r.masked, "hi  bye");
    }

    #[test]
    fn empty_masker_rejected() {
        let r = Masker::builder().build();
        assert!(r.is_err());
    }

    #[test]
    fn with_all_builtins_works() {
        let m = Masker::with_all_builtins().unwrap();
        let r = m.mask("ip 10.0.0.1 ssn 123-45-6789", Strategy::Tag);
        assert!(r.matches.iter().any(|m| m.kind == "IPV4"));
        assert!(r.matches.iter().any(|m| m.kind == "US_SSN"));
    }

    #[test]
    fn luhn_known_valid_numbers() {
        // Visa, MasterCard, Amex test numbers.
        for n in ["4111111111111111", "5500000000000004", "340000000000009"] {
            assert!(is_luhn_valid(n), "{n} should be Luhn-valid");
        }
    }

    #[test]
    fn luhn_known_invalid() {
        for n in ["1234567890123456", "0000000000000000123"] {
            assert!(!is_luhn_valid(n), "{n} should be Luhn-invalid");
        }
    }

    #[test]
    fn match_offsets_are_byte_accurate() {
        let m = email_masker();
        let text = "hi alice@example.com bye";
        let r = m.mask(text, Strategy::Tag);
        let m0 = &r.matches[0];
        assert_eq!(&text[m0.start..m0.end], "alice@example.com");
    }

    #[test]
    fn keyword_with_empty_needles_skipped() {
        // Empty needle list shouldn't crash AhoCorasick, just be ignored.
        let m = Masker::builder()
            .with_builtin(BuiltinRule::Email)
            .with_keywords("ignored", &[])
            .build()
            .unwrap();
        let r = m.mask("a@b.com", Strategy::Tag);
        assert_eq!(r.masked, "<EMAIL>");
    }

    #[test]
    fn unicode_safe_in_input() {
        let m = email_masker();
        let r = m.mask("hello 世界 a@b.com 🌍", Strategy::Tag);
        assert_eq!(r.masked, "hello 世界 <EMAIL> 🌍");
    }
}
