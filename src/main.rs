use std::io::{stdin, Read};
use std::process::exit;

use distributed_bss::{CombinedGPK, Signature};
use serde::{Deserialize, Serialize};

fn main() -> Result<(), String> {
    let mut args = std::env::args();

    match args.next().as_deref() {
        Some("verify") => {
            let mut buffer = String::new();
            stdin()
                .read_to_string(&mut buffer)
                .map_err(|_| "failed to read from stdin".to_string())?;
            let res = verify(&buffer)?;

            // 0 if success, or else others
            let code = !res as i32;
            exit(code);
        }
        _ => exit(1),
    }
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
