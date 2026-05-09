# maskprompt-core

Pure-Rust core for [maskprompt](https://github.com/MukundaKatta/maskprompt):
PII redaction for LLM prompts.

```rust
use maskprompt_core::{BuiltinRule, Masker, Strategy};

let masker = Masker::builder()
    .with_builtin(BuiltinRule::Email)
    .with_keywords("customer", &["Acme Corp"])
    .build()?;
let result = masker.mask(
    "Email alice@example.com about Acme Corp.",
    Strategy::Tag,
);
assert_eq!(result.masked, "Email <EMAIL> about <CUSTOMER>.");
# Ok::<(), maskprompt_core::MaskerError>(())
```

## License

Dual-licensed under MIT or Apache-2.0.
