use std::convert::TryFrom;
use std::io::{stdin, Read};
use std::process::exit;

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
            let ok = verify(&buffer)?;

            let code = if ok {
                println!("OK");
                0
            } else {
                println!("NG");
                1
            };

            exit(code);
        }
        _ => {
            println!("{}", usage(&name));
            exit(1);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct VerifyParams {
    message: Vec<u8>,
    signature: String,
    gpk: String,
}

pub fn verify(params_bytes: &[u8]) -> Result<bool, String> {
    let params = VerifyParams::try_from(params_bytes)?;
    let signature =
        serde_json::from_str(&params.signature).or(Err("Failed to deserialize signature"))?;
    let gpk = serde_json::from_str(&params.gpk).or(Err("Failed to decode gpk"))?;

    let result = distributed_bss::verify(&params.message, &signature, &gpk).is_ok();
    return Ok(result);
}

impl TryFrom<&[u8]> for VerifyParams {
    type Error = String;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // {signature}\n
        // {gpk}\n
        // {message
        // ...
        // }
        let lines: Vec<_> = bytes.splitn(3, |b| *b == b'\n').collect();
        if lines.len() < 3 {
            return Err("not enough inputs".to_string());
        }

        let signature = String::from_utf8_lossy(lines[0]).into_owned();
        let gpk = String::from_utf8_lossy(lines[1]).into_owned();
        let message = lines[2].to_owned();

        Ok(Self {
            message,
            signature,
            gpk,
        })
    }
}

impl VerifyParams {
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.signature.as_bytes(),
            b"\n",
            self.gpk.as_bytes(),
            b"\n",
            &self.message,
        ]
        .concat()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        // sorry kino-ma
        use distributed_bss::gm::{GMId, GM};
        use distributed_bss::{CombinedGPK, CombinedUSK};
        use rand::thread_rng;

        let mut rng = thread_rng();

        let gm1 = GM::random(GMId::One, &mut rng);
        let gm2 = GM::random(GMId::Two, &mut rng);
        let gm3 = GM::random(GMId::Three, &mut rng);

        let u = gm1.gen_combined_pubkey(&gm2.gpk.h);
        let v = gm2.gen_combined_pubkey(&gm3.gpk.h);
        let w = gm3.gen_combined_pubkey(&gm1.gpk.h);

        let h = gm3.gen_combined_pubkey(&u);

        let partials = vec![
            gm1.issue_member(&mut rng),
            gm2.issue_member(&mut rng),
            gm3.issue_member(&mut rng),
        ];

        let partical_gpks = vec![gm1.gpk, gm2.gpk, gm3.gpk];

        let gpk = CombinedGPK {
            h,
            partical_gpks,
            u,
            v,
            w,
        };

        let message = String::from("hoge").as_bytes().to_vec();
        let message2 = String::from("piyo").as_bytes().to_vec();

        let usk = CombinedUSK::new(&partials);
        let signature = distributed_bss::sign(&message, &usk, &gpk, &mut rng);

        let gpk = serde_json::to_string(&gpk).unwrap();
        let signature = serde_json::to_string(&signature).unwrap();

        let params = VerifyParams {
            message,
            signature: signature.clone(),
            gpk: gpk.clone(),
        };
        let data = params.to_bytes();

        let res = verify(&data).expect("failed to verify");

        assert!(res);

        let params = VerifyParams {
            message: message2,
            signature,
            gpk,
        };
        let data = params.to_bytes();

        let res = verify(&data).expect("failed to verify");
        assert!(!res);
    }

    #[test]
    fn convert_to_correct_bytes() {
        let expect = "someSignature
someGpk
someMessage"
            .as_bytes();

        let actual = get_sample().to_bytes();
        assert_eq!(expect, actual);
    }

    #[test]
    fn can_parse_params() {
        let expect = get_sample();
        let s = expect.to_bytes();
        let actual = VerifyParams::try_from(&*s).expect("failed to parse");

        assert_eq!(expect, actual);
    }

    #[test]
    #[ignore]
    fn sample_encode() {
        let params = get_sample();
        let txt = serde_json::to_string(&params).expect("failed to encode");
        println!("{}", txt);
    }

    fn get_sample() -> VerifyParams {
        VerifyParams {
            message: "someMessage".as_bytes().to_owned(),
            signature: "someSignature".to_string(),
            gpk: "someGpk".to_string(),
        }
    }
}
