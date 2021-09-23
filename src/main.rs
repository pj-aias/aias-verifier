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
    fn test_real_data() {
        let signature = r#"{"t1":[163,118,147,27,52,132,237,77,232,104,9,167,240,208,77,221,5,203,59,141,252,235,149,154,61,14,199,81,125,203,221,208,82,168,137,159,72,177,122,146,19,248,59,245,19,60,232,84],"t2":[172,85,235,198,76,238,89,242,146,16,208,230,90,251,143,82,135,113,17,225,240,79,35,90,32,72,39,23,109,228,171,159,9,213,5,44,109,21,193,4,149,146,0,110,14,190,210,190],"t3":[173,46,185,226,43,239,235,176,80,88,203,254,11,98,138,16,242,222,76,82,150,187,232,135,89,67,86,96,176,111,242,140,125,83,52,255,2,8,2,150,235,133,127,28,78,113,104,1],"t4":[[173,188,118,156,217,219,223,25,83,93,11,45,40,132,154,227,212,4,18,97,38,5,118,251,46,85,88,100,65,133,197,95,234,227,88,124,140,168,3,208,86,185,182,231,167,72,252,79],[146,19,51,27,206,249,183,9,0,8,245,100,204,6,184,206,54,45,71,62,3,228,17,128,89,77,47,219,73,96,226,238,70,2,31,170,55,207,193,184,146,234,223,206,90,208,221,109],[151,70,158,231,21,161,52,88,110,182,144,194,237,165,234,151,148,125,223,246,210,229,176,201,131,147,227,113,145,83,65,238,43,34,214,191,226,90,243,13,102,160,60,221,221,152,183,122]],"hash":[192,26,219,42,82,176,176,178,34,118,183,102,66,118,171,249,94,218,27,161,51,190,153,37,80,108,252,18,123,177,44,57],"sa":[51,221,137,89,191,133,79,160,193,7,132,211,124,245,126,197,188,40,181,106,30,8,233,243,11,67,63,231,135,149,178,14],"sb":[109,231,134,196,174,63,157,141,121,240,20,134,132,118,82,173,131,1,157,94,103,16,17,100,25,244,63,8,178,255,111,62],"sc":[154,96,173,130,173,136,110,165,202,235,11,14,4,41,227,197,178,248,39,178,163,42,180,17,97,174,79,15,228,219,189,107],"sx":[[227,35,13,87,148,108,113,5,107,107,145,175,200,208,136,168,188,177,150,173,46,127,77,32,50,12,107,114,105,105,101,108],[248,119,223,207,122,45,88,127,231,39,41,74,220,9,138,145,106,116,219,5,141,251,115,164,195,49,22,54,210,11,81,42],[21,17,227,100,163,74,22,189,209,220,17,98,194,60,19,125,105,194,245,244,168,66,202,121,100,169,78,177,183,174,6,0]],"s_delta1":[[235,71,53,163,158,230,223,229,238,93,247,77,65,231,237,148,67,217,91,133,42,254,254,182,126,140,102,160,212,1,207,110],[38,144,133,40,44,73,176,155,206,191,39,50,220,175,197,183,62,45,167,7,189,208,23,14,102,38,54,106,95,211,155,8],[234,115,149,121,37,21,224,229,84,186,118,80,220,245,184,25,143,7,253,181,44,132,77,177,65,158,101,134,11,224,244,88]],"s_delta2":[[216,246,4,16,13,32,4,6,201,25,94,188,221,246,84,152,92,251,40,95,7,26,150,36,87,0,170,20,218,86,241,100],[216,66,102,196,55,47,149,111,20,185,81,186,4,238,65,194,100,135,174,68,138,56,205,84,88,34,66,177,111,104,163,109],[18,20,223,56,82,172,181,208,197,204,244,15,202,244,30,250,201,14,240,238,36,212,182,198,239,41,247,17,139,61,93,97]],"s_delta3":[[127,107,130,119,15,45,82,222,146,151,104,241,24,232,171,8,200,173,33,25,94,114,92,8,121,54,236,140,110,2,165,101],[233,54,159,203,177,204,142,30,194,30,161,96,75,236,185,6,13,169,175,201,250,46,183,34,248,164,83,34,122,103,12,68],[234,160,34,203,251,118,5,191,174,189,100,95,108,66,145,205,80,35,14,40,254,96,253,17,24,121,245,4,110,238,178,79]]}"#.to_string();
        let gpk = r#"{"h":[182,195,226,162,184,185,133,39,231,4,4,67,96,251,182,140,235,10,49,73,27,220,252,160,197,7,233,246,159,253,131,196,125,213,163,167,206,65,183,154,223,106,231,225,118,157,170,131],"u":[151,96,174,19,241,138,252,142,109,51,223,148,255,139,228,245,81,225,141,11,173,232,1,248,102,184,166,206,64,212,114,242,25,94,148,173,112,239,252,37,46,60,236,207,83,239,49,138],"v":[151,96,174,19,241,138,252,142,109,51,223,148,255,139,228,245,81,225,141,11,173,232,1,248,102,184,166,206,64,212,114,242,25,94,148,173,112,239,252,37,46,60,236,207,83,239,49,138],"w":[151,96,174,19,241,138,252,142,109,51,223,148,255,139,228,245,81,225,141,11,173,232,1,248,102,184,166,206,64,212,114,242,25,94,148,173,112,239,252,37,46,60,236,207,83,239,49,138],"partical_gpks":[{"h":[128,84,198,180,77,86,22,44,6,207,69,150,195,104,208,200,145,56,12,114,244,77,110,246,214,79,162,5,241,9,1,159,15,2,135,165,39,190,121,5,70,55,104,44,65,120,34,129],"omega":[169,234,89,107,32,166,222,237,78,216,15,89,253,218,248,20,158,130,144,137,238,250,128,91,69,154,56,129,78,229,5,171,206,81,15,47,56,169,107,120,54,221,173,73,238,36,71,92,16,158,244,153,47,152,148,223,226,174,79,50,46,57,242,180,53,87,110,238,47,164,58,120,140,43,159,179,234,133,197,171,220,242,58,238,223,171,48,76,116,4,46,238,106,220,168,163]},{"h":[128,84,198,180,77,86,22,44,6,207,69,150,195,104,208,200,145,56,12,114,244,77,110,246,214,79,162,5,241,9,1,159,15,2,135,165,39,190,121,5,70,55,104,44,65,120,34,129],"omega":[169,234,89,107,32,166,222,237,78,216,15,89,253,218,248,20,158,130,144,137,238,250,128,91,69,154,56,129,78,229,5,171,206,81,15,47,56,169,107,120,54,221,173,73,238,36,71,92,16,158,244,153,47,152,148,223,226,174,79,50,46,57,242,180,53,87,110,238,47,164,58,120,140,43,159,179,234,133,197,171,220,242,58,238,223,171,48,76,116,4,46,238,106,220,168,163]},{"h":[128,84,198,180,77,86,22,44,6,207,69,150,195,104,208,200,145,56,12,114,244,77,110,246,214,79,162,5,241,9,1,159,15,2,135,165,39,190,121,5,70,55,104,44,65,120,34,129],"omega":[169,234,89,107,32,166,222,237,78,216,15,89,253,218,248,20,158,130,144,137,238,250,128,91,69,154,56,129,78,229,5,171,206,81,15,47,56,169,107,120,54,221,173,73,238,36,71,92,16,158,244,153,47,152,148,223,226,174,79,50,46,57,242,180,53,87,110,238,47,164,58,120,140,43,159,179,234,133,197,171,220,242,58,238,223,171,48,76,116,4,46,238,106,220,168,163]}]}"#.to_string();
        let message = r#"{"username":"Xxvv","password":"ccthvvf","signature":"test"}"#
            .to_string()
            .as_bytes()
            .to_vec();

        let data = VerifyParams {
            message,
            signature,
            gpk,
        };
        let res = verify(&data.to_bytes()).expect("failed to verify");
        assert!(res);
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
