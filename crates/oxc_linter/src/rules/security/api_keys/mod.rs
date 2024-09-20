mod entropy;
#[allow(unused_imports, unused_variables)]
mod secret;
mod secrets;

use std::{num::NonZeroU32, ops::Deref};

use oxc_ast::AstKind;
use oxc_diagnostics::OxcDiagnostic;
use oxc_macros::declare_oxc_lint;
use oxc_span::GetSpan;

use entropy::Entropy;
use secret::{Secret, SecretScanner, SecretScannerMeta, SecretViolation};
use secrets::{SecretsEnum, ALL_RULES};

use crate::{context::LintContext, rule::Rule, AstNode};

fn api_keys(violation: &SecretViolation) -> OxcDiagnostic {
    OxcDiagnostic::warn(violation.message().to_owned())
        .with_error_code_num(format!("api-keys/{}", violation.rule_name()))
        .with_label(violation.span())
        .with_help(
            "Use a secrets manager to store your API keys securely, then read them at runtime.",
        )
}

declare_oxc_lint!(
    /// ### What it does
    ///
    ///
    /// ### Why is this bad?
    ///
    ///
    /// ### Examples
    ///
    /// Examples of **incorrect** code for this rule:
    /// ```js
    /// FIXME: Tests will fail if examples are missing or syntactically incorrect.
    /// ```
    ///
    /// Examples of **correct** code for this rule:
    /// ```js
    /// FIXME: Tests will fail if examples are missing or syntactically incorrect.
    /// ```
    ApiKeys,
    nursery, // TODO: change category to `correctness`, `suspicious`, `pedantic`, `perf`, `restriction`, or `style`
             // See <https://oxc.rs/docs/contribute/linter.html#rule-category> for details

    pending  // TODO: describe fix capabilities. Remove if no fix can be done,
             // keep at 'pending' if you think one could be added but don't know how.
             // Options are 'fix', 'fix_dangerous', 'suggestion', and 'conditional_fix_suggestion'
);

#[derive(Debug, Default, Clone)]
pub struct ApiKeys(Box<ApiKeysInner>);

#[derive(Debug, Clone)]
pub struct ApiKeysInner {
    min_len: NonZeroU32,
    min_entropy: f32,
    rules: Vec<SecretsEnum>,
}

impl Default for ApiKeysInner {
    fn default() -> Self {
        Self::new(ALL_RULES.clone())
    }
}

impl ApiKeysInner {
    pub fn new(rules: Vec<SecretsEnum>) -> Self {
        let min_len = rules.iter().map(secrets::SecretsEnum::min_len).min().unwrap();
        let min_entropy = rules.iter().map(secrets::SecretsEnum::min_entropy).fold(0.0, f32::min);

        Self { min_len, min_entropy, rules }
    }
}

impl Deref for ApiKeys {
    type Target = ApiKeysInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ApiKeysInner {}

impl Rule for ApiKeys {
    fn run<'a>(&self, node: &AstNode<'a>, ctx: &LintContext<'a>) {
        let string: &'a str = match node.kind() {
            AstKind::StringLiteral(string) => string.value.as_str(),
            AstKind::TemplateLiteral(string) => {
                let Some(string) = string.quasi() else {
                    return;
                };
                string.as_str()
            }
            _ => return,
        };

        // skip strings that are below the length/entropy threshold of _all_ rules. Perf
        // optimization, avoid O(n) len/entropy checks (for n rules)
        if string.len() < self.min_len.get() as usize {
            return;
        }
        let candidate = Secret::new(string, node.span(), None);
        if candidate.entropy() < self.min_entropy {
            return;
        }

        for rule in &self.rules {
            // order here is important: they're in order of cheapest to most expensive
            if candidate.len() < rule.min_len().get() as usize
                || candidate.entropy() < rule.min_entropy()
                || !rule.detect(&candidate)
            {
                continue;
            }

            // This clone allocs no memory and so is relatively cheap. rustc should optimize it
            // away anyways.
            let mut violation = SecretViolation::new(candidate.clone(), rule);
            if rule.verify(&mut violation) {
                ctx.diagnostic(api_keys(&violation));
                return;
            }
        }
    }
}

#[test]
fn test() {
    use crate::tester::Tester;

    let pass: Vec<&str> = vec![];

    let fail = vec![];

    Tester::new(ApiKeys::NAME, pass, fail).test_and_snapshot();
}
