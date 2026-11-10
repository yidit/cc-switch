//! 内置检测器。

pub mod account;
pub mod email;
pub mod phone;
pub mod secret;

pub use account::AccountDetector;
pub use email::EmailDetector;
pub use phone::PhoneDetector;
pub use secret::SecretDetector;
