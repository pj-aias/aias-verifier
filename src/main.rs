use std::io::{stdin, Read};
use std::process::exit;

use distributed_bss::{CombinedGPK, Signature};
use serde::{Deserialize, Serialize};

fn usage(name: &str) -> String {
    return format!(
        "usage:\t {} verify\n\n\
        Read parameters (message, signature, and gpk from stdin, in the rmp format.",
        name
    );
}

fn main() -> Result<(), String> {
    let mut args = std::env::args();
    let name = args.next().unwrap();

    match args.next().as_deref() {
        Some("verify") => {
            let mut buffer = Vec::new();
            stdin()
                .read_to_end(&mut buffer)
                .map_err(|_| "failed to read from stdin".to_string())?;
            let res = verify(&buffer)?;

            // 0 if success, or else others
            let code = !res as i32;
            exit(code);
        }
        _ => {
            println!("{}", usage(&name));
            exit(1);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct VerifyParams {
    message: Vec<u8>,
    signature: Signature,
    gpk: CombinedGPK,
}

pub fn verify(params_bytes: &[u8]) -> Result<bool, String> {
    let params: VerifyParams =
        rmp_serde::from_read(params_bytes).or(Err("Failed to decode input".to_string()))?;

    let VerifyParams {
        message,
        signature,
        gpk,
    } = params;

    let result = distributed_bss::verify(&message, &signature, &gpk).is_ok();
    return Ok(result);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verifies_ok() {
        // msg: hoge
        let encoded_params = "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";
        let params = base64::decode(encoded_params).expect("failed to convert from base64");

        let res = verify(&params).expect("failed to verify");

        assert!(res);
    }

    #[test]
    fn denies_ng() {
        // signed msg is hoge, but passing fuga
        let encoded_params = "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";
        let params = base64::decode(encoded_params).expect("failed to convert from base64");

        let res = verify(&params).expect("failed to verify");

        assert!(!res);
    }
}
