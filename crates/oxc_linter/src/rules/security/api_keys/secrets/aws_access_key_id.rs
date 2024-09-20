use std::num::NonZeroU32;

use super::{Secret, SecretScanner, SecretScannerMeta};

#[derive(Debug, Default, Clone)]
pub struct AwsAccessKeyId;

impl SecretScannerMeta for AwsAccessKeyId {
    fn rule_name(&self) -> &'static str {
        "aws-access-key-id"
    }

    fn message(&self) -> &'static str {
        "Detected an AWS Access Key ID, which can be used to access AWS resources."
    }

    fn min_len(&self) -> NonZeroU32 {
        // SAFETY: 20 is a valid value for NonZeroU32
        unsafe { NonZeroU32::new_unchecked(20) }
    }

    fn min_entropy(&self) -> f32 {
        4.0
    }
}
impl SecretScanner for AwsAccessKeyId {
    fn detect(&self, candidate: &Secret<'_>) -> bool {
        candidate.starts_with("AKIA")
    }
}
