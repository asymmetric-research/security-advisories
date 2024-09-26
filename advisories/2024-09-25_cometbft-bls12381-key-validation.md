# Missing BLS12-381 Public Key Validation

## Description

CometBFT latest available release is v1.0.0-rc1.0.20240805092115-3b2c5d9e1843, which introduces support for BLS signatures over the BLS12-381 curve. In this release, instantiation of BLS public keys from byte arrays is done via `github.com/cosmos/crypto v0.0.0-20240309083813-82ed2537802e`, a clone of the Prysm's wrapper over BLST, as it can be seen at: https://github.com/cometbft/cometbft/blob/86da0027d878707365c16b124b77892ca5212fe1/crypto/bls12381/key_bls12381.go#L127 The `PublicKeyFromBytes` function performs the G1 subgroup and infinity check with a call to BLST's `KeyValidate`: https://github.com/cosmos/crypto/blob/bb8c5deb91b3a722e145c4d9c6d06c6158d23dfe/curves/bls12381/pubkey.go#L64

CometBFT current main branch, as of September, 11, dropped the dependency above, and it has introduced a new function `NewPublicKeyFromBytes`: https://github.com/cometbft/cometbft/blob/237f30dcd2224585716e45a01fbcecf48adbff85/crypto/bls12381/key_bls12381.go#L160

This function performs the deserialization of the point but **omits** the checks above.

BLST's `Deserialize` function is a Go wrapper over `blst_p1_deserialize`, which deserializes and uncompresses the point; the deserialization verifies that the point lies on the multiplicative group here: https://github.com/supranational/blst/blob/52cc60d78591a56abb2f3d0bd1cdafc6ba242997/src/e1.c#L318 but this check does not verify that the point lies in the secure subgroup of G1.

No further invocation of `KeyValidate` have been found in the CometBFT main branch.

## Proof of Concept

We refer to Ethereum Beacon Protocol test vectors for BLS12-381: https://github.com/ethereum/bls12-381-tests. We retrieve the three points under:

- `deserialization_G1/deserialization_fails_not_in_G1.json`
- `deserialization_G1/eserialization_fails_infinity_with_false_b_flag.json`
- `deserialization_G1/eserialization_fails_infinity_with_true_b_flag.json`

referred in the code below, respectively, as:

        "NotInG1"       : "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "InfFalseB"     : "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "InfTrueB"      : "c01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",

We require the main branch in the `go.mod` and compile with `go build -tags bls12381`, in order to enable support for BLS12-381.

```go
package main

import (
        "fmt"
        "encoding/hex"
        "errors"

        blst "github.com/supranational/blst/bindings/go"
        prysmbls "github.com/prysmaticlabs/prysm/v5/crypto/bls"
        cometbls "github.com/cometbft/cometbft/crypto/bls12381"
)

type blstPublicKey = blst.P1Affine

func G1PKPrysm(pk string) error {
        infp, err := hex.DecodeString(pk)
        if err != nil {
                return err
        }
        _ , err = prysmbls.PublicKeyFromBytes(infp)
        if err != nil {
                return err
        }
        return nil
}

func G1PKCometBft(pk string) error {
        if !cometbls.Enabled {
                return errors.New("BLS12-381 not enabled")
        }
        infp, err := hex.DecodeString(pk)
        if err != nil {
                return err
        }

        p := new(blstPublicKey).Uncompress(infp)
        if p == nil {
                return errors.New("could not unmarshal bytes into public key")
        }

        infpSer := p.Serialize()
        if infpSer == nil {
                return errors.New("Could not serialize public key")
        }
        _ , err = cometbls.NewPublicKeyFromBytes(infpSer)
        if err != nil {
                return err
        }
        return nil
}

func main() {
        cs := map[string]string {
                "NotInG1"       : "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "InfFalseB"     : "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "InfTrueB"      : "c01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        }
        var err any
        for k, v := range cs {
                if err = G1PKPrysm(v); err != nil {
                        fmt.Println("Prysm:", k, err)
                } else {
                        fmt.Println("Prysm:", k, "Ok")
                }
                if err = G1PKCometBft(v); err != nil {
                        fmt.Println("CometBft:", k, err)
                } else {
                        fmt.Println("CometBft:", k, "Ok")
                }
        }
}
```

We obtain the following output:

```
Prysm: NotInG1 received an infinite public key
CometBft: NotInG1 Ok
Prysm: InfFalseB could not unmarshal bytes into public key
CometBft: InfFalseB could not unmarshal bytes into public key
Prysm: InfTrueB could not unmarshal bytes into public key
CometBft: InfTrueB could not unmarshal bytes into public key

```
The second line means that the point `NotInG1` was deserialized correctly by `NewPublicKeyFromBytes` with no further checks, whereas Prysm rejected it (although with an incorrect error message).

## Impact

The subgroup check ensures that the public key is a point on the subgroup of prime order `r` of the curve. The omission would not only allow for computations in arbitrary groups but, assuming a Cosmos application using the BLS12-381 keys for a key-exchange protocol, an attacker whose public key is not validated could induce the other participant in the protocol to inadvertently perform computations with her secret key on the invalid public key, an operation which is known to leak data about the secret key [1].

## Fix

https://github.com/cometbft/cometbft/pull/4104

## References

[1] Chae Hoon Lim and Pil Joong Lee, A Key Recovery Attack on Discrete Log-based Schemes Using a Prime Order Subgroup.
