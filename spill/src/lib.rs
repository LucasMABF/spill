mod channel;
mod error;

pub use channel::{Channel, ChannelParams};
pub use error::{ConfigError, FinalizeError, FundingError, PaymentError, SpillError};
