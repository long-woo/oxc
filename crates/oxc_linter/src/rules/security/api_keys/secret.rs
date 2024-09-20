use std::{borrow::Cow, num::NonZeroU32, ops::Deref};

use oxc_span::{Atom, GetSpan, Span};

use super::{Entropy, SecretsEnum};

#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone)]
pub struct Secret<'a> {
    secret: &'a str,
    /// Secret span
    span: Span,
    /// TODO: find and pass identifiers once we have rules that need it
    #[allow(dead_code)]
    identifier: Option<Atom<'a>>,
    entropy: f32,
}

#[derive(Debug, Clone)]
pub struct SecretViolation<'a> {
    secret: Secret<'a>,
    rule_name: Cow<'a, str>, // really should be &'static
    message: Cow<'a, str>,   // really should be &'static
}

/// Detects hard-coded API keys and other credentials.
pub trait SecretScannerMeta {
    /// Human-readable unique identifier describing what service this rule finds api keys for.
    /// Must be kebab-case.
    fn rule_name(&self) -> &'static str;

    fn message(&self) -> &'static str;

    /// Min str length a key candidate must have to be considered a violation. Must be >= 1.
    #[inline]
    fn min_len(&self) -> NonZeroU32 {
        // SAFETY: 8 is a valid value for NonZeroU32
        unsafe { NonZeroU32::new_unchecked(8) }
    }

    /// Min entropy a key must have to be considered a violation. Must be >= 0.
    ///
    /// Defaults to 0.5
    #[inline]
    fn min_entropy(&self) -> f32 {
        0.5
    }
}

pub trait SecretScanner: SecretScannerMeta {
    fn detect(&self, candidate: &Secret<'_>) -> bool;

    #[inline]
    fn verify(&self, violation: &mut SecretViolation<'_>) -> bool {
        true
    }
}

impl<'a> Secret<'a> {
    pub fn new(secret: &'a str, span: Span, identifier: Option<Atom<'a>>) -> Self {
        let entropy = secret.entropy();
        Self { secret, span, identifier, entropy }
    }
}
impl Deref for Secret<'_> {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.secret
    }
}

impl Entropy for Secret<'_> {
    #[inline]
    fn entropy(&self) -> f32 {
        self.entropy
    }
}

impl GetSpan for Secret<'_> {
    #[inline]
    fn span(&self) -> Span {
        self.span
    }
}

impl<'a> SecretViolation<'a> {
    pub fn new(secret: Secret<'a>, rule: &SecretsEnum) -> Self {
        Self {
            secret,
            rule_name: Cow::Borrowed(rule.rule_name()),
            message: Cow::Borrowed(rule.message()),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn rule_name(&self) -> &str {
        &self.rule_name
    }
}

impl GetSpan for SecretViolation<'_> {
    #[inline]
    fn span(&self) -> Span {
        self.secret.span()
    }
}
