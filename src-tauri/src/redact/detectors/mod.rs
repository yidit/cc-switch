//! 内置检测器。

pub mod account;
pub mod email;
pub mod phone;
pub mod rules;
pub mod secret;
pub mod words;

pub use account::AccountDetector;
pub use email::EmailDetector;
pub use phone::PhoneDetector;
pub use rules::CustomRuleDetector;
pub use secret::SecretDetector;
pub use words::WordDetector;
