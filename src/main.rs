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
            self.gpk.as_bytes(),
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
        // msg: hoge
        let encoded_params = "k5Rob2dl2gacbk53QU1NeTRDc3o2VDh6UHpLRkVhUk1weko1WEVjeUZ6SkFLSk16eXpKUUp6SXNjekpiTTNVc2R6SUFNTk16NUJFY3hKSHBJS0g1NUhCUE1zTXlnUGN6QnpLVE16ejNjQURETWhsMDN6SnpNblZiTXVNeUx6S0VLUlZITXpCdk04bHpNeWN5WXpNdk11Y3kxZHpOZnpJdDlRTXpHYURyTWpzeTRHRXZNd2N5WVljeXZCemJNL3N6ZHpJd3VWOHlCRUNmY0FERE1wOHk3R1RJdXpPYzFmOHpMek5RMVJjeVFmOHlpek9WZkZzejJ6TFpXek8wVktjei96UFpiektETXEzUE16blZ2SW1iTXNteHd6SXpNc1M4L1hVczRKUWpNL1pQY0FERE1yOHpoQWkxZ1NNeW16SjlNekwzTWs4eU5mY3pGTTh6a3pORE0zV1hNKzh6bUZ4cGN6T2JNbzh6VnpKdk04TXl6eklaYXpPSW9Jc3lsVlZYTXNWVW96SjdNOXoxeHpQek1oSG5jQURETWpzempKMThMek1yTW5tN01tVjhUek1ZYXpNTXJZMGpNaWp0ZHpOSitIY3kyekxvUWRNemR6SmZNbGhGZUhFak0wOHlzZWtITTVzenBXOHp6ek1OZnpPcGt6SUZzM0FBd3pJYk1tUlVKek5CSHpQdDd6TE5pTWlKREIzN01oVXdnekxuTWw4eWJ6SWNqek5nK0Y4eVl6SVhNdU16QXpNN00xaXZNOWk3TXFNeVdPbi9NamN5RmUzbzl6TjNNMk15dldOd0FJRElkektYTStrSjd6SUxNbDh6RE1YUlF6TFhNbHN6TEZSbk1sY3loekpYTWk4eVVaTXo3ek80L2NEdk1yY3orQ1ZMY0FDQjFmV1RNL2N6VXpJNTlCY3ltekt6TWo4eW5ROHkrekpETW1VM00yVGwwTHN5enpJeCtjY3o5TWczTWxzejN6SjBVM0FBZ0FzeWJGc3lGelAzTTFzeit6UDNNdTJETWpsOHh6SjRvWE16eHpNTE1oMmpNM1RJUHpKUE15Y3prUUZETTNTb1JWZHdBSUE3TTZoZk0wMkliWmg5WVA4eml6SklETHN6VXpKak05Y3lXQmtiTWpjeUFUazNNM3N6MVVXMGF6T1hNN2dhVDNBQWd6SUlTRm1zU05TSUlWY3lYekpVSnpQWVhPRFFLeklrNnpKYk05Y3luZGN6b3pPWVJPRVF6RTh6SE05d0FJTXlSVm1FV2R3VE00Y3pWSndKRkRpd3h6SUxNNWN5NnpQa0N6TmQzRmN5VHpMSTN6SUlPek1qTTM4eml6T0kzM0FBZ0FNemVITXkyeko5NEJEYk0xa0FNek03TTRzeVV6UFBNeE15cWJjeW9XVC9NN015UE1RM01rbnd0WURITXVVeVQzQUFnek1iTW9jejh6TmpNd0Y3TXdzeWl6Si9NN1RoZXpPVVRERUU1U016enpQek04TXlmSTh6dExNeXp6TjNNaEQxM3pMTkUzQUFnekpiTW1VL015c3lZek5ITTNjeWp6UDAzUUJ2TXJCM00xTXlNelBMTXAyOTVPRFV3SkRkc3pKVE14eUpkek5BNzNBQWdBc3pPekxjUnpLYzhSM2RNekkvTW9nL01tc3paTjh5UnpNczF6UERNa1h6TXJnN01wTXp0ek96TTlRVWVMOHlFRjVQY0FDRE0rbTdNbGo5MXpQWE11c3pMek5yTW5zelRWOHlPWXkxSUVjempLc3lQY015SHpLRUh6SlRNdTh5T0M4eXplbkl5M0FBZ1JUM015TXpCekw1K3pKc0F6S2JNOXN5d2JNeVl6TG5Nejh6S1BNeUx6TFl5ekpaTVBNeTl6SURNMXN5UVVjeWtEUllXM0FBZ0lERm1RQ25NNlF6TW9uTTNac3kzek9ETXhjemFOempNd1hFbHpPQTh6Sm5NenN6M0Q4ekZVQWpNeGN6cFE1UGNBQ0JEekk0ZXpMVE10Y3lvek1OeUhuTE0xY3pQek4wZFg4eUNmOHlMek4vTXRFN01nUU51ekpQTTZCQU1Jc3pwRjAzY0FDQjNGc3o2T016RnpOOWd6TUZ4elBiTTZ4dk0xOHp6WUJzcEg4eStLVDA0ek9zRnpJTE0rOHl5ek5kMHpLSUxaOXdBSU16ZnpMVk56UERNcmN5M0ljejRJOHpCekxNRnpKWmtNRjNNOWpITXNzeWF6S1BNcmN6Q1BzeU56TC9NMzh5TXpJRktmMGM92gUYbGR3QU1NeXJHMUlGek5WT3pJWE1zemJNMjh5aFNuUE0rOHp5ekpQTTljekF6T0JZekxiTXlNeXB6THhkek9JSnpQdk16bnBCek9NR3pOczF6TXpNc0ZETXNzeVJ6TFRNa3N6R3pQSE1rOHpkUzh6azNBQXd6TGpNcjh6a01rVE1tTXpwTVh3N1Rjem5SMlpwTmtmTTg4emV6UFBNdUJ2TStNelN6T3RIS2N6ZHpNa2lGMXRaeko3TW1zekRheHM4ek1UTTYzUVV6SXgwelAvTW1EM2NBRERNcEVqTXhNeW96TlUwekxYTTkxSE15TXlVelBrQXpPVWxPc3p1SDBETWhNemV6TEJKekxITWsyWE10TXkxeklQTXREOXB6S2JNMDh6M1dRc3l6TEluZFU0UnpQM001Y3prQk16NTNBQXd6STVYVHN5Yk5ISE16SGJNd015NHpQUnRBY3pkS1NmTTFIUE0vWFp2ektjMExneEp6T3dCek40enpPOXhia3NmekpuTTZrNGhVeU1OQnN5WXpLTE0yVnpNMTVPUzNBQXd6SlBNME16SnpPck14Y3lmRzMxWEQwN01pQlBNbHN6YVJzeVN6SThwQm1BMnpNNW16UDNNaDFUTWtjejNLOHpOUGtmTXY4ek1TVlIzek8xTHpLYk0yOHp0R1VsbHpNQm0zQUJneklSSnpNM01vVGtlWWN5dHpLek1zMnR4Y0VITTZzeWpkVEkySTBGTFpNeXJ6SkxNb016QXpPY0l6UGZNcWN6VHpMeHpMZ3JNNUNCV2VqRE1yc3phRk16N3pQM001c3pqQWczTXdoYk1rM0pKek9iTW44ekdkY3pFUDh5U2ZjeUV6TlZPZHpsYlhtYk15TXlmTVhQTTBRc0p6TDNNaE15RU14cDNMMDBKek5JRUljem16T1JwT2dGTGt0d0FNTXk1ek5MTXJzelpYc3ozek5ITTU4emhHaDNNdTh5OEhsSkt6UElHYnlyTXJNemV6TFhNakZqTXNEVE16TXorekxNL3pQbk1rMURNN2N5OEVzeWhYY3p2elBMTXNNelNmc3pQek4zTThjelYzQUJnekpnenpOck1wTXk4ekx3aGNNeVlTY3lJelBITTJzeVZDc3pIZkRVanpMek0yUlVvektiTWhzeVR6THd5ektqTW9zeWJFWGZNaVJSalBjeWtDazAvek1UTXpzeWp6S1pOek9RYUJjeWVHc3lMTk16NlRzeWtBeWxtSGN5SnpKSE0zTXpXekk1anpJM01uejF0R015QXpMc3RYMG5NMzh6RkV3QXV6TURNbk15dGNjenFYY3pOVlFCanpLZk12c3k4TE16dmt0d0FNTXlCek1VTXpLTE1qbDRnTWxCL3pNM01xbWpNbEFseHpQRTh6Tjh6ekxUTTJBMUV6TnZNdFFsenpQWSt6T3BKekt2TXA4ejRjOHo3Rlh0bUFRYk15Y3prekxMTXo4enpmTndBWU15T1lzei9IMUJPWHhUTTJRL016elFzRU15bE54UE13TXljVHN5aHpQL01sRUFZekozTTY4eW1hM3JNaUZ4aGZuQmx6Si9NbGtuTTkxY0tSY3pMSFZYTTRjeXZFOHlQZEE3TW5zeXVjTXlnek41dnpJSTlaSEJjYUZ2TStWaGN6TjdNaHN5Z2U4elp6TVBNL2l6TTJNeXl6TUY1U3N6MEE4ejF6SUpaeks5ald5Yk1pc3lUekpUTXBrVWc=";
        let params = base64::decode(encoded_params).expect("failed to convert from base64");

        let res = verify(&params).expect("failed to verify");

        assert!(res);
    }

    #[test]
    fn denies_ng() {
        // signed msg is hoge, but passing fuga
        let encoded_params = "k5RmdWdh2gacbk53QU1NeTRDc3o2VDh6UHpLRkVhUk1weko1WEVjeUZ6SkFLSk16eXpKUUp6SXNjekpiTTNVc2R6SUFNTk16NUJFY3hKSHBJS0g1NUhCUE1zTXlnUGN6QnpLVE16ejNjQURETWhsMDN6SnpNblZiTXVNeUx6S0VLUlZITXpCdk04bHpNeWN5WXpNdk11Y3kxZHpOZnpJdDlRTXpHYURyTWpzeTRHRXZNd2N5WVljeXZCemJNL3N6ZHpJd3VWOHlCRUNmY0FERE1wOHk3R1RJdXpPYzFmOHpMek5RMVJjeVFmOHlpek9WZkZzejJ6TFpXek8wVktjei96UFpiektETXEzUE16blZ2SW1iTXNteHd6SXpNc1M4L1hVczRKUWpNL1pQY0FERE1yOHpoQWkxZ1NNeW16SjlNekwzTWs4eU5mY3pGTTh6a3pORE0zV1hNKzh6bUZ4cGN6T2JNbzh6VnpKdk04TXl6eklaYXpPSW9Jc3lsVlZYTXNWVW96SjdNOXoxeHpQek1oSG5jQURETWpzempKMThMek1yTW5tN01tVjhUek1ZYXpNTXJZMGpNaWp0ZHpOSitIY3kyekxvUWRNemR6SmZNbGhGZUhFak0wOHlzZWtITTVzenBXOHp6ek1OZnpPcGt6SUZzM0FBd3pJYk1tUlVKek5CSHpQdDd6TE5pTWlKREIzN01oVXdnekxuTWw4eWJ6SWNqek5nK0Y4eVl6SVhNdU16QXpNN00xaXZNOWk3TXFNeVdPbi9NamN5RmUzbzl6TjNNMk15dldOd0FJRElkektYTStrSjd6SUxNbDh6RE1YUlF6TFhNbHN6TEZSbk1sY3loekpYTWk4eVVaTXo3ek80L2NEdk1yY3orQ1ZMY0FDQjFmV1RNL2N6VXpJNTlCY3ltekt6TWo4eW5ROHkrekpETW1VM00yVGwwTHN5enpJeCtjY3o5TWczTWxzejN6SjBVM0FBZ0FzeWJGc3lGelAzTTFzeit6UDNNdTJETWpsOHh6SjRvWE16eHpNTE1oMmpNM1RJUHpKUE15Y3prUUZETTNTb1JWZHdBSUE3TTZoZk0wMkliWmg5WVA4eml6SklETHN6VXpKak05Y3lXQmtiTWpjeUFUazNNM3N6MVVXMGF6T1hNN2dhVDNBQWd6SUlTRm1zU05TSUlWY3lYekpVSnpQWVhPRFFLeklrNnpKYk05Y3luZGN6b3pPWVJPRVF6RTh6SE05d0FJTXlSVm1FV2R3VE00Y3pWSndKRkRpd3h6SUxNNWN5NnpQa0N6TmQzRmN5VHpMSTN6SUlPek1qTTM4eml6T0kzM0FBZ0FNemVITXkyeko5NEJEYk0xa0FNek03TTRzeVV6UFBNeE15cWJjeW9XVC9NN015UE1RM01rbnd0WURITXVVeVQzQUFnek1iTW9jejh6TmpNd0Y3TXdzeWl6Si9NN1RoZXpPVVRERUU1U016enpQek04TXlmSTh6dExNeXp6TjNNaEQxM3pMTkUzQUFnekpiTW1VL015c3lZek5ITTNjeWp6UDAzUUJ2TXJCM00xTXlNelBMTXAyOTVPRFV3SkRkc3pKVE14eUpkek5BNzNBQWdBc3pPekxjUnpLYzhSM2RNekkvTW9nL01tc3paTjh5UnpNczF6UERNa1h6TXJnN01wTXp0ek96TTlRVWVMOHlFRjVQY0FDRE0rbTdNbGo5MXpQWE11c3pMek5yTW5zelRWOHlPWXkxSUVjempLc3lQY015SHpLRUh6SlRNdTh5T0M4eXplbkl5M0FBZ1JUM015TXpCekw1K3pKc0F6S2JNOXN5d2JNeVl6TG5Nejh6S1BNeUx6TFl5ekpaTVBNeTl6SURNMXN5UVVjeWtEUllXM0FBZ0lERm1RQ25NNlF6TW9uTTNac3kzek9ETXhjemFOempNd1hFbHpPQTh6Sm5NenN6M0Q4ekZVQWpNeGN6cFE1UGNBQ0JEekk0ZXpMVE10Y3lvek1OeUhuTE0xY3pQek4wZFg4eUNmOHlMek4vTXRFN01nUU51ekpQTTZCQU1Jc3pwRjAzY0FDQjNGc3o2T016RnpOOWd6TUZ4elBiTTZ4dk0xOHp6WUJzcEg4eStLVDA0ek9zRnpJTE0rOHl5ek5kMHpLSUxaOXdBSU16ZnpMVk56UERNcmN5M0ljejRJOHpCekxNRnpKWmtNRjNNOWpITXNzeWF6S1BNcmN6Q1BzeU56TC9NMzh5TXpJRktmMGM92gUYbGR3QU1NeXJHMUlGek5WT3pJWE1zemJNMjh5aFNuUE0rOHp5ekpQTTljekF6T0JZekxiTXlNeXB6THhkek9JSnpQdk16bnBCek9NR3pOczF6TXpNc0ZETXNzeVJ6TFRNa3N6R3pQSE1rOHpkUzh6azNBQXd6TGpNcjh6a01rVE1tTXpwTVh3N1Rjem5SMlpwTmtmTTg4emV6UFBNdUJ2TStNelN6T3RIS2N6ZHpNa2lGMXRaeko3TW1zekRheHM4ek1UTTYzUVV6SXgwelAvTW1EM2NBRERNcEVqTXhNeW96TlUwekxYTTkxSE15TXlVelBrQXpPVWxPc3p1SDBETWhNemV6TEJKekxITWsyWE10TXkxeklQTXREOXB6S2JNMDh6M1dRc3l6TEluZFU0UnpQM001Y3prQk16NTNBQXd6STVYVHN5Yk5ISE16SGJNd015NHpQUnRBY3pkS1NmTTFIUE0vWFp2ektjMExneEp6T3dCek40enpPOXhia3NmekpuTTZrNGhVeU1OQnN5WXpLTE0yVnpNMTVPUzNBQXd6SlBNME16SnpPck14Y3lmRzMxWEQwN01pQlBNbHN6YVJzeVN6SThwQm1BMnpNNW16UDNNaDFUTWtjejNLOHpOUGtmTXY4ek1TVlIzek8xTHpLYk0yOHp0R1VsbHpNQm0zQUJneklSSnpNM01vVGtlWWN5dHpLek1zMnR4Y0VITTZzeWpkVEkySTBGTFpNeXJ6SkxNb016QXpPY0l6UGZNcWN6VHpMeHpMZ3JNNUNCV2VqRE1yc3phRk16N3pQM001c3pqQWczTXdoYk1rM0pKek9iTW44ekdkY3pFUDh5U2ZjeUV6TlZPZHpsYlhtYk15TXlmTVhQTTBRc0p6TDNNaE15RU14cDNMMDBKek5JRUljem16T1JwT2dGTGt0d0FNTXk1ek5MTXJzelpYc3ozek5ITTU4emhHaDNNdTh5OEhsSkt6UElHYnlyTXJNemV6TFhNakZqTXNEVE16TXorekxNL3pQbk1rMURNN2N5OEVzeWhYY3p2elBMTXNNelNmc3pQek4zTThjelYzQUJnekpnenpOck1wTXk4ekx3aGNNeVlTY3lJelBITTJzeVZDc3pIZkRVanpMek0yUlVvektiTWhzeVR6THd5ektqTW9zeWJFWGZNaVJSalBjeWtDazAvek1UTXpzeWp6S1pOek9RYUJjeWVHc3lMTk16NlRzeWtBeWxtSGN5SnpKSE0zTXpXekk1anpJM01uejF0R015QXpMc3RYMG5NMzh6RkV3QXV6TURNbk15dGNjenFYY3pOVlFCanpLZk12c3k4TE16dmt0d0FNTXlCek1VTXpLTE1qbDRnTWxCL3pNM01xbWpNbEFseHpQRTh6Tjh6ekxUTTJBMUV6TnZNdFFsenpQWSt6T3BKekt2TXA4ejRjOHo3Rlh0bUFRYk15Y3prekxMTXo4enpmTndBWU15T1lzei9IMUJPWHhUTTJRL016elFzRU15bE54UE13TXljVHN5aHpQL01sRUFZekozTTY4eW1hM3JNaUZ4aGZuQmx6Si9NbGtuTTkxY0tSY3pMSFZYTTRjeXZFOHlQZEE3TW5zeXVjTXlnek41dnpJSTlaSEJjYUZ2TStWaGN6TjdNaHN5Z2U4elp6TVBNL2l6TTJNeXl6TUY1U3N6MEE4ejF6SUpaeks5ald5Yk1pc3lUekpUTXBrVWc=";
        let params = base64::decode(encoded_params).expect("failed to convert from base64");

        let res = verify(&params).expect("failed to verify");

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
    fn accepts_from_outside() {
        // from Go using sample
        let sample = "someSignature
someGpk
someMessage";

        let expect = get_sample();
        let actual = VerifyParams::try_from(sample.as_bytes()).expect("failed to parse");

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
