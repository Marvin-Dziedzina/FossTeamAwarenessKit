use serde::{Deserialize, Serialize};

pub fn get_json_result<D: Serialize>(data: D) -> String {
    let data = Response::new(data);

    serde_json::to_string(&data).unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response<D> {
    time_stamp: u128,
    data: D,
}
impl<D> Response<D> {
    pub fn new(data: D) -> Self {
        Self {
            time_stamp: crate::get_unix_epoch_timestamp(),
            data,
        }
    }
}
