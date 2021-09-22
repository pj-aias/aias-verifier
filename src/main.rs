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
    let message = params.message;

    let signature_bin = base64::decode(params.signature).or(Err("Failed to decode signature"))?;
    let signature =
        rmp_serde::from_read(&*signature_bin).or(Err("Failed to deserialize signature"))?;

    let gpk_bin = base64::decode(params.gpk).or(Err("Failed to decode gpk"))?;
    let gpk = rmp_serde::from_read(&*gpk_bin).or(Err("Failed to deserialize gpk"))?;

    let result = distributed_bss::verify(&message, &signature, &gpk).is_ok();
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
    fn verifies_ok() {
        let message = b"hoge".to_vec();
        let signature = "nNwAMMylOyvMhMztzPsbQsyXzIXMki7Mi8zNPQrMuszqB0PM7Sp6zJrMqUrMqnjMnhLM/RvM08yhzIBEzLd1QFMxzMvM2Mz4D1zM9gbcADDMocz6SczPzKPMn8zxzLrMwE41zNzM4WhqBX/MmMzmzJTMhDgnzMoSzL7MiBfMlsylMszfzJBCYXvM18yyzM16zKIkRF1XzKt/zPfcADDMocyMzKTMzszTzL1izO14GMzpGsyhMsy4zPDMgczqzOXM8MzbHcyazKHMtBMBzJPMm0vMoszGbczAAMyQesz9YTAEN0xEzMQ2zOt8k9wAMMyxzPPMz38iex/MtXpKzLTMzAJSzJbMl3XMmMyEzMTMtgnMsW3My8yTzL9LJ8yZzPvM3nh2M8zZzIY7HsybPMyIYczpzJF1zLY/3AAwzIZTzKHM1icvzOtIzMzM0MzUzOzM1szTfwI/zOAzzIDM6lPM5mINzO5BzM3M08zjOw/M2D7MqszlzLrMjcy6zKrMs1t9KMzFLMz8zOzcADDMqm1mYMyffszaNDLM1wkhLczWRMyRcszIzPthzNnM18z/NMz4OUsozKxrLFvMqxhxzNVOHsyGzLzM839vSMzoEcyoHdwAIMyqGlQlJMzYzIjM1UssHA/M82J3zO/M/ns0dMynZh4wzLLMhHvM7TQ1UW7cACDMoszizKZLzLDMtsy/zLUieQfM0szaRBhEcwbM4My4zPnM0czNR8zdzPHMnFvM5GQBAdwAIMzKzIfM6szIzObM31N+CF4wRwvMrHXMgGQDzIZLLSdTzIwwFcyqzLTMhczFzJ003AAgeczizNw4InY0LmZJzObMmszzzN3M0k7MvW1QGczRzN/Mt1U2zLdGERFUJw2T3AAgzLQJAx/Mr3DMnWbMgcyBzNvM7BIdWRHMv8zazInMzcztzMtJzNYEFcyqHnrM0mI73AAgzI7M3szyzNXM4cyMLcyYCszvX8zAzLAxzPB/zMjM4VfMsMzHYWstzKpBzPbMlX7MlcyhRdwAIMzgHk/M28zezKvM2UMONMzGeczARUAtRsyuFczJc8yheB1uzPkXcMyvSsyxBJPcACBkzP3Mt8y9MMyxzM3M08zCzJ/M1mnMl8ydzPUhzKLMviECzM3Mk8zmDMyBUFnM8syBzIfM1AXcACDMrszqzOUzzK7M38ygzNx1VGUyzKJPHMy4fm7M+syIzNN0zLnMrMyxzJcZTcytzMbMoV7cACDM137MzA19cFBTzI0jzJhgzNd9aMyxzJA1zL8ezJ5jZsybzLHMvj9czIbM2D5Hk9wAIDfMisyHMlfM1gHMmRDM4My3zNwoNMzmcczBzLkWUGwRzPvM58zizIHMtszODHwsZdwAIFjM8MzLzPdfzOvMkSLMvszXacz3zKkuDknMmgLMw8yCZszUzPt5zJN5CBTMoxzMhx/cACBiLMz6zP7MtxjM5H0fSU/Mp8zuBszDzI8VcMymzITMqEIyIEDMiXfMv8zJzIETcJPcACDMkMyPzIAVccyAzOccRWlBMsz4GMyCAiB6WgvMnCQczPLM6MzBPzXM+MzFzM1R3AAgzPTMzArM+sz6Ccz2SxXM1HU4FRVyzJFRzIEnMsyhJC/M3B3Mlsy4HXrMhMzjCdwAIAcazJ3M/T/Mscy1TMyRPczrNMyETcypIMyvHsyszPHMl8ywzI7Mm8zSzN43PzgWzOEV".to_string();
        let gpk = "ldwAMMy1UczUKDjM8BbMjmXM28yXMhgdTUTMpCF8dczSSMzLe0AsMsyDPDgLzKLM0gXMn2PMvknMpsyZVjATG1TMpRrMutwAMMyrzN8VY1I5zPB3QD/MuQpkzNVOzIbM8FjMuMyybMydzPDM1szIzLrMucyTPB03W8zTzJUnzOXM4wbM48yTH8z8zJMfSszZzKY13AAwzJbM1BYqaGtkb8zmXTHM4MzqzKFUEMzgJHDMyczNdiALcczjzIENEARGF0FpzOpRSgDM4kfM7TLMwsytzLJKzLbM8NwAMMyTJDQvH8yAzMwbUTAJEmFTeXBPzInMusyfzKjMzwoRBMzuO1bM62fMzXAnzI8mzOIYzLLM8z7M5szOzI4xasz4f8ylk5LcADDMuczMzL01P3/MtErMuHPMtcznY8zhYcywzLY9zII4YTJ+DwXMwyjMvcyqMhdiZAXMqRzMoszHZ8zYzLvMs8zyzMPMnwnM3syJ3ABgzIZVDjkdzJLMk8yJzLcHzLfMjHsSL0wuzI8XzLg+zMPMn8yAXMzmIhAEYXrMlztWExEhDMyzWCHM0cyXSyvMwnDMhgbMjVV7AcyizIzM0TtJEszszJomCszSLhvMvczpTgpozLNkX1rMjsyMIGh3RWTMuwUsWCTMkiwyzJrMkszfOWgkktwAMMywzMJ2zP/MozrMiMyqOszVB8yMzMUpzJVtzIbM6FfMoBd1zPw8WszLD1bMhTh/cMyPe1wxQTDM6R7Mh0hhMHxNzKjMo9wAYMyqchU6zKcYHczJzLN0zOrMmcy/zIPMuAvMszkQBhTM+czozPdlzPdPzPVdzJfMn8zBzIjMyQhya8zszL3MwjoBzJ5ZzKokT8yMAMy8zIQmLAnMusynzOJqzORmzJLMj2BUXiXMwsy7LVPM8sytzLzM5AEAGsymzLzMlmTMxGjM/8yBzIvMhMyGzMo2zLDMt8zBzIfMnczYktwAMMySzJ7M1QhgUsyHbMz1WszwzPUnzIxmVszXbFjMvFV9VwTMnCQuWSLMtczvzOYazLolzJHMqszdzO7M4y0TJRkPR3dQ3ABgzK3MjljMp8zCcBnM38yVP8zhGcydzKXMnsyjFxNrzJPM08ypzLzMoWXMvUbMwMyefMyYO2ljzJQWKwbM08zczOAQFcyDW8yvTnIXzK/M4cyCDcyFzLdNzP9tL13M8nTM3lQRzJp6zJLMiFrM5jsYez0ZKF0VzJtAzILM+24kzPTMwcz5zKMzzK7MzX7MrSQK".to_string();
        let params = VerifyParams {
            message,
            signature,
            gpk,
        };
        let data = params.to_bytes();

        let res = verify(&data).expect("failed to verify");

        assert!(res);
    }

    #[test]
    fn denies_ng() {
        // signed message is hoge, but passing fuga
        let message = b"fuga".to_vec();
        let signature = "nNwAMMylOyvMhMztzPsbQsyXzIXMki7Mi8zNPQrMuszqB0PM7Sp6zJrMqUrMqnjMnhLM/RvM08yhzIBEzLd1QFMxzMvM2Mz4D1zM9gbcADDMocz6SczPzKPMn8zxzLrMwE41zNzM4WhqBX/MmMzmzJTMhDgnzMoSzL7MiBfMlsylMszfzJBCYXvM18yyzM16zKIkRF1XzKt/zPfcADDMocyMzKTMzszTzL1izO14GMzpGsyhMsy4zPDMgczqzOXM8MzbHcyazKHMtBMBzJPMm0vMoszGbczAAMyQesz9YTAEN0xEzMQ2zOt8k9wAMMyxzPPMz38iex/MtXpKzLTMzAJSzJbMl3XMmMyEzMTMtgnMsW3My8yTzL9LJ8yZzPvM3nh2M8zZzIY7HsybPMyIYczpzJF1zLY/3AAwzIZTzKHM1icvzOtIzMzM0MzUzOzM1szTfwI/zOAzzIDM6lPM5mINzO5BzM3M08zjOw/M2D7MqszlzLrMjcy6zKrMs1t9KMzFLMz8zOzcADDMqm1mYMyffszaNDLM1wkhLczWRMyRcszIzPthzNnM18z/NMz4OUsozKxrLFvMqxhxzNVOHsyGzLzM839vSMzoEcyoHdwAIMyqGlQlJMzYzIjM1UssHA/M82J3zO/M/ns0dMynZh4wzLLMhHvM7TQ1UW7cACDMoszizKZLzLDMtsy/zLUieQfM0szaRBhEcwbM4My4zPnM0czNR8zdzPHMnFvM5GQBAdwAIMzKzIfM6szIzObM31N+CF4wRwvMrHXMgGQDzIZLLSdTzIwwFcyqzLTMhczFzJ003AAgeczizNw4InY0LmZJzObMmszzzN3M0k7MvW1QGczRzN/Mt1U2zLdGERFUJw2T3AAgzLQJAx/Mr3DMnWbMgcyBzNvM7BIdWRHMv8zazInMzcztzMtJzNYEFcyqHnrM0mI73AAgzI7M3szyzNXM4cyMLcyYCszvX8zAzLAxzPB/zMjM4VfMsMzHYWstzKpBzPbMlX7MlcyhRdwAIMzgHk/M28zezKvM2UMONMzGeczARUAtRsyuFczJc8yheB1uzPkXcMyvSsyxBJPcACBkzP3Mt8y9MMyxzM3M08zCzJ/M1mnMl8ydzPUhzKLMviECzM3Mk8zmDMyBUFnM8syBzIfM1AXcACDMrszqzOUzzK7M38ygzNx1VGUyzKJPHMy4fm7M+syIzNN0zLnMrMyxzJcZTcytzMbMoV7cACDM137MzA19cFBTzI0jzJhgzNd9aMyxzJA1zL8ezJ5jZsybzLHMvj9czIbM2D5Hk9wAIDfMisyHMlfM1gHMmRDM4My3zNwoNMzmcczBzLkWUGwRzPvM58zizIHMtszODHwsZdwAIFjM8MzLzPdfzOvMkSLMvszXacz3zKkuDknMmgLMw8yCZszUzPt5zJN5CBTMoxzMhx/cACBiLMz6zP7MtxjM5H0fSU/Mp8zuBszDzI8VcMymzITMqEIyIEDMiXfMv8zJzIETcJPcACDMkMyPzIAVccyAzOccRWlBMsz4GMyCAiB6WgvMnCQczPLM6MzBPzXM+MzFzM1R3AAgzPTMzArM+sz6Ccz2SxXM1HU4FRVyzJFRzIEnMsyhJC/M3B3Mlsy4HXrMhMzjCdwAIAcazJ3M/T/Mscy1TMyRPczrNMyETcypIMyvHsyszPHMl8ywzI7Mm8zSzN43PzgWzOEV".to_string();
        let gpk = "ldwAMMy1UczUKDjM8BbMjmXM28yXMhgdTUTMpCF8dczSSMzLe0AsMsyDPDgLzKLM0gXMn2PMvknMpsyZVjATG1TMpRrMutwAMMyrzN8VY1I5zPB3QD/MuQpkzNVOzIbM8FjMuMyybMydzPDM1szIzLrMucyTPB03W8zTzJUnzOXM4wbM48yTH8z8zJMfSszZzKY13AAwzJbM1BYqaGtkb8zmXTHM4MzqzKFUEMzgJHDMyczNdiALcczjzIENEARGF0FpzOpRSgDM4kfM7TLMwsytzLJKzLbM8NwAMMyTJDQvH8yAzMwbUTAJEmFTeXBPzInMusyfzKjMzwoRBMzuO1bM62fMzXAnzI8mzOIYzLLM8z7M5szOzI4xasz4f8ylk5LcADDMuczMzL01P3/MtErMuHPMtcznY8zhYcywzLY9zII4YTJ+DwXMwyjMvcyqMhdiZAXMqRzMoszHZ8zYzLvMs8zyzMPMnwnM3syJ3ABgzIZVDjkdzJLMk8yJzLcHzLfMjHsSL0wuzI8XzLg+zMPMn8yAXMzmIhAEYXrMlztWExEhDMyzWCHM0cyXSyvMwnDMhgbMjVV7AcyizIzM0TtJEszszJomCszSLhvMvczpTgpozLNkX1rMjsyMIGh3RWTMuwUsWCTMkiwyzJrMkszfOWgkktwAMMywzMJ2zP/MozrMiMyqOszVB8yMzMUpzJVtzIbM6FfMoBd1zPw8WszLD1bMhTh/cMyPe1wxQTDM6R7Mh0hhMHxNzKjMo9wAYMyqchU6zKcYHczJzLN0zOrMmcy/zIPMuAvMszkQBhTM+czozPdlzPdPzPVdzJfMn8zBzIjMyQhya8zszL3MwjoBzJ5ZzKokT8yMAMy8zIQmLAnMusynzOJqzORmzJLMj2BUXiXMwsy7LVPM8sytzLzM5AEAGsymzLzMlmTMxGjM/8yBzIvMhMyGzMo2zLDMt8zBzIfMnczYktwAMMySzJ7M1QhgUsyHbMz1WszwzPUnzIxmVszXbFjMvFV9VwTMnCQuWSLMtczvzOYazLolzJHMqszdzO7M4y0TJRkPR3dQ3ABgzK3MjljMp8zCcBnM38yVP8zhGcydzKXMnsyjFxNrzJPM08ypzLzMoWXMvUbMwMyefMyYO2ljzJQWKwbM08zczOAQFcyDW8yvTnIXzK/M4cyCDcyFzLdNzP9tL13M8nTM3lQRzJp6zJLMiFrM5jsYez0ZKF0VzJtAzILM+24kzPTMwcz5zKMzzK7MzX7MrSQK".to_string();
        let params = VerifyParams {
            message,
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
        let raw = rmp_serde::to_vec(&params).expect("failed to encode");

        let txt = base64::encode(raw);
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
