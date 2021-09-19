# AIAS Verifier
Verifies AIAS signature.

## Usage
Accepts parameters in the MessagePack format.

Required parameters:

```
{
    "message": [byte],
    "signature": string, // base64
    "gpk": string // base64
}
```

To run, from command line:

```sh
cargo build --release
target/release/aias-verifier verify < parameter.msgpack
```

Exit code will be `0` if passed verification, and others if failed.