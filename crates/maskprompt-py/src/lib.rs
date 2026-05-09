//! PyO3 bindings exposing `maskprompt_core` as `maskprompt._native`.

use maskprompt_core::{BuiltinRule, MaskMatch, Masker, MaskerError, Strategy};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

pyo3::create_exception!(_native, MaskpromptError, pyo3::exceptions::PyException);

fn map_err(e: MaskerError) -> PyErr {
    match e {
        MaskerError::InvalidConfig(msg) => PyValueError::new_err(msg),
        other => MaskpromptError::new_err(other.to_string()),
    }
}

fn rule_from_str(name: &str) -> PyResult<BuiltinRule> {
    Ok(match name.to_uppercase().as_str() {
        "EMAIL" => BuiltinRule::Email,
        "US_PHONE" => BuiltinRule::UsPhone,
        "US_SSN" => BuiltinRule::UsSsn,
        "IPV4" => BuiltinRule::Ipv4,
        "IPV6" => BuiltinRule::Ipv6,
        "CREDIT_CARD" => BuiltinRule::CreditCard,
        "AWS_ACCESS_KEY" => BuiltinRule::AwsAccessKey,
        "GITHUB_TOKEN" => BuiltinRule::GithubToken,
        "JWT" => BuiltinRule::Jwt,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown built-in rule: {other}"
            )))
        }
    })
}

fn strategy_from_str(name: &str) -> PyResult<Strategy> {
    Ok(match name.to_lowercase().as_str() {
        "tag" => Strategy::Tag,
        "hash" => Strategy::Hash,
        "fixed" => Strategy::Fixed,
        "remove" => Strategy::Remove,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown strategy: {other} (expected tag/hash/fixed/remove)"
            )))
        }
    })
}

#[pyclass(name = "Masker", module = "maskprompt._native")]
struct PyMasker {
    inner: Masker,
}

#[pymethods]
impl PyMasker {
    /// Build a Masker from a list of built-in rule names and a label->needles dict.
    #[new]
    #[pyo3(signature = (builtins=None, custom=None))]
    fn new(builtins: Option<Vec<String>>, custom: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut b = Masker::builder();
        if let Some(names) = builtins {
            for n in names {
                b = b.with_builtin(rule_from_str(&n)?);
            }
        }
        if let Some(custom) = custom {
            for (label, needles) in custom.iter() {
                let label_s: String = label.extract()?;
                let needles_v: Vec<String> = needles.extract()?;
                let refs: Vec<&str> = needles_v.iter().map(String::as_str).collect();
                b = b.with_keywords(label_s, &refs);
            }
        }
        let inner = b.build().map_err(map_err)?;
        Ok(Self { inner })
    }

    /// Mask `text` and return a dict shaped like the Python `MaskResult`.
    #[pyo3(signature = (text, strategy="tag"))]
    fn mask<'py>(
        &self,
        py: Python<'py>,
        text: &str,
        strategy: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let strat = strategy_from_str(strategy)?;
        let owned = text.to_owned();
        let result = py.allow_threads(move || self.inner.mask(&owned, strat));
        let dict = PyDict::new(py);
        dict.set_item("masked", result.masked)?;
        let matches = PyList::empty(py);
        for m in result.matches {
            matches.append(match_to_dict(py, &m)?)?;
        }
        dict.set_item("matches", matches)?;
        Ok(dict)
    }

    /// Bulk variant. Same `strategy` is applied to each input.
    #[pyo3(signature = (texts, strategy="tag"))]
    fn mask_batch<'py>(
        &self,
        py: Python<'py>,
        texts: Vec<String>,
        strategy: &str,
    ) -> PyResult<Bound<'py, PyList>> {
        let strat = strategy_from_str(strategy)?;
        let results = py.allow_threads(move || {
            texts
                .iter()
                .map(|t| self.inner.mask(t, strat))
                .collect::<Vec<_>>()
        });
        let out = PyList::empty(py);
        for r in results {
            let dict = PyDict::new(py);
            dict.set_item("masked", r.masked)?;
            let matches = PyList::empty(py);
            for m in r.matches {
                matches.append(match_to_dict(py, &m)?)?;
            }
            dict.set_item("matches", matches)?;
            out.append(dict)?;
        }
        Ok(out)
    }

    fn __repr__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        Ok(PyString::new(py, "Masker(...)"))
    }
}

fn match_to_dict<'py>(py: Python<'py>, m: &MaskMatch) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("kind", &m.kind)?;
    d.set_item("start", m.start)?;
    d.set_item("end", m.end)?;
    d.set_item("value", &m.value)?;
    Ok(d)
}

/// Module-level list of built-in rule names (uppercase tags).
#[pyfunction]
fn builtin_rule_names() -> Vec<&'static str> {
    BuiltinRule::all().iter().map(|r| r.tag()).collect()
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("MaskpromptError", m.py().get_type::<MaskpromptError>())?;
    m.add_class::<PyMasker>()?;
    m.add_function(wrap_pyfunction!(builtin_rule_names, m)?)?;
    Ok(())
}
