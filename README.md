# Physical Coin Certificate Verifier


## Introduction

For use with digital certificates for monero physical coins (specifically Lealana physical coins).
A monero daemon must be running locally to check the outputs and their spent status, but signatures can be checked without a daemon running.

* Checks the hash of the message against the hash on the certificate (sha256), and gives a warning if they do not match.
* Checks signatures
* Checks output info exists on blockchain and belongs to the address/viewkey in the certificates
* Checks spent status of all outputs on the certificate
* Exits with an error message at the first error (either the first failed signature check or, if signatures are good, the first output which
  could not be found when querying the daemon).

## License

See [LICENSE](LICENSE).


## Build instructions

### On Linux

* Install the dependencies (Same dependencies as monero)
* Change to the root of the source code directory and build:
* Run `get_libwallet_api.sh` to download and compile the merged wallet library.
* Run `make` to compile (or `make testnet` to compile the binaries for testnet wallets/addresses).
  The resulting executables `certificate_verifier` and `sample_certificate` can be found in `verifier_package/build/bin`.



## Usage

* `certificate_verifier` 1) checks signatures, 2) checks that outputs exist, belong to the given address and are of the correct amount, 3) checks the spent status of all outputs.

        certificate_verifier <certificate filename>

    You must be running `monerod` for `certificate_verifier` to check that the outputs exist and to check their spent status.  Example certificates, produced for testnet wallets,
    can be found in the `test_certificates` subdirectory.  There should only be one certificate in the file specified by <certificate filename>.

* `sample_certificate` produces a sample certificate (for testing purposes) using the wallet specified by wallet-name.  Wallet.keys file and Wallet file must be present.

        sample_certificate <wallet name>  [<output filename>]

    A daemon does not need to be running but the wallet needs to be up-to-date to produce an accurate certificate.
