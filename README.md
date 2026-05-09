# maskprompt

Sub-millisecond PII redaction for prompts before they reach an LLM.
Rust core, Python frontend.

## The problem

Compliance wants you to scrub PII before it leaves your VPC and hits an
external LLM API. Pure-Python regex passes are not nothing, but they cost
hundreds of microseconds per prompt at the p99 and they make the security
team nervous because the patterns drift.

`maskprompt` runs the standard PII detectors (email, phone, credit card
with Luhn, SSN, IP addresses, AWS keys, GitHub PATs, JWT) plus your own
keyword/phrase lists in a single Aho-Corasick + regex pass, and replaces
matches with one of four configurable strategies. The whole thing runs
in microseconds at typical prompt sizes.

## Install

```bash
pip install maskprompt
```

## 30-second quickstart

```python
from maskprompt import Masker, BuiltinRule, Strategy

masker = Masker(
    builtins=[BuiltinRule.EMAIL, BuiltinRule.CREDIT_CARD, BuiltinRule.US_SSN],
    custom={"customer": ["Acme Corp"]},  # your own labels
)

text = "Email me at alice@example.com about Acme Corp invoice 4111-1111-1111-1111."
result = masker.mask(text, strategy=Strategy.TAG)

print(result.masked)
# Email me at <EMAIL> about <CUSTOMER> invoice <CREDIT_CARD>.

for m in result.matches:
    print(m.kind, m.start, m.end)
```

## Strategies

| Strategy | Replacement | Use it when |
|---|---|---|
| `Strategy.TAG` | `<EMAIL>` | Default. The LLM sees the type but not the value. |
| `Strategy.HASH` | `<EMAIL:abc12345>` | You need to track "the same redacted value showed up again" without recovering it. blake3 over the original, truncated to 8 hex chars. |
| `Strategy.FIXED` | `███████` | Length-preserving for visual cues. |
| `Strategy.REMOVE` | _(empty)_ | When even the type is too much information. |

## Built-in detectors

| Rule | Catches |
|---|---|
| `EMAIL` | RFC-5322-ish addresses |
| `US_PHONE` | US 10-digit and `+1` formats |
| `US_SSN` | `XXX-XX-XXXX` |
| `IPV4` | dotted quad |
| `IPV6` | `::` and full forms |
| `CREDIT_CARD` | 13–19-digit candidates that pass Luhn |
| `AWS_ACCESS_KEY` | `AKIA…` 20-char keys |
| `GITHUB_TOKEN` | `ghp_/gho_/ghu_/ghr_/ghs_…` |
| `JWT` | three base64url segments separated by `.` |

Pick the subset you want; unmentioned detectors are off.

## Custom keywords

`custom={"label": ["needle1", "needle2"]}` labels are case-insensitive and
match on word-character boundaries. Pass several labels to tag distinct
groups (`{"customer": [...], "internal_project": [...]}`).

## License

Dual-licensed under MIT or Apache-2.0 at your option.
