use std::time::{self, UNIX_EPOCH};

pub fn get_unix_epoch_timestamp() -> u128 {
    time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System before UNIX epoch!")
        .as_millis()
}
