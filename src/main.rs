use std::io::{stdin, Read};

use distributed_bss::{CombinedGPK, Signature};
use serde::{Deserialize, Serialize};

fn main() {
    let mut buffer = String::new();
    stdin()
        .read_to_string(&mut buffer)
        .expect("failed to read from stdin");
}

#[derive(Serialize, Deserialize)]
struct VerifyParams {
    message: String,
    signature: Signature,
    gpk: CombinedGPK,
}

pub fn verify(params_str: &str) -> Result<bool, String> {
    let params: VerifyParams = rmp_serde::from_read(params_str.as_bytes())
        .or(Err("Failed to decode input".to_string()))?;

    let VerifyParams {
        message,
        signature,
        gpk,
    } = params;

    let result = distributed_bss::verify(message.as_bytes(), &signature, &gpk).is_ok();
    return Ok(result);
}
