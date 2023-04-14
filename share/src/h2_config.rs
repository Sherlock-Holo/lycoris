use std::time::Duration;

/// 20 MiB
pub const INITIAL_WINDOW_SIZE: u32 = 20 * 1024 * 1024;
/// 100 MiB
pub const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 100 * 1024 * 1024;
/// the h2 lib allow max size
pub const MAX_FRAME_SIZE: u32 = 16777215;
/// ping interval
pub const PING_INTERVAL: Duration = Duration::from_secs(10);
/// ping timeout
pub const TIMEOUT: Duration = Duration::from_secs(10);
