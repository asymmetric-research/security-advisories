# BLS12-381 Wrong Signature Generation 

## Description

CometBFT has introduced support for BLS signatures over the BLS12-381 curve. The support is a set of functions wrapping over `blst`'s Go bindings. The signature method of type `PrivKey` at https://github.com/cometbft/cometbft/blob/276996ad958475b69727be2c57d4d0d818849a55/crypto/bls12381/key_bls12381.go#L110
adds a conditional branch to discern whether the message to sign, a byte slice, is longer than 32 bytes; in such case, the slice is hashed with `sha256`, and `blst`'s `Sign` method (of type `blst.P2Affine`) is called on the message digest, instead of the original message.

Not only is this addition superflous but it alters the strength of the hash-to-curve construction of the underlying `blst` library.

The `blst` library strictly follows [RFC 9380, "Hashing to curve"](https://datatracker.ietf.org/doc/html/rfc9380) when it comes to hashing arbitrary strings to one of the two subgroups G1 or G2 of the BLS12-381 curve. This operation requires the input string to be first hashed to the underlying field, before mapping the resulting field element to the given group (in the present case, G2).  This is better seen by inspecting `blst`'s `Sign` method at https://github.com/supranational/blst/blob/cf754001ddd10c30c366a2d6337e2a1a82bd6acf/bindings/go/blst.go#L503 In the absence of any optional arguments, as it is always the case in CometBFT (because it invokes the latter function always without optional arguments), `useHash` is always `true` as per `parseOpts` (and `augSingle` is `nil`). Therefore, the function `HashToG2` is always the one to be invoked in our case. `HashToG2` will then invoke the C function `blst_hash_to_g2` at https://github.com/supranational/blst/blob/cf754001ddd10c30c366a2d6337e2a1a82bd6acf/bindings/go/blst.go#L2747C4-L2747C19 The latter function ends up calling `hash_to_field`, as it can be seen at https://github.com/supranational/blst/blob/cf754001ddd10c30c366a2d6337e2a1a82bd6acf/src/map_to_g2.c#L388-L401

It is important to realize that `hash_to_field` already performs the hashing operation via `sha256`, regardless of the input size; furthermore, in order to reduce the inherent bias due to the modulo `p` operation, it performs an expansion (see `expand_message_xmd`), as per the RFC above. The function can be seen here: https://github.com/supranational/blst/blob/cf754001ddd10c30c366a2d6337e2a1a82bd6acf/src/hash_to_field.c#L120

This is the strongest form of hashing to field, as it ensures the output to be indifferentiable from a random oracle. However, CometBFT's pre-hash makes the construction distinguishable from uniformly random. To see why, consider the following example:

```go
package main

import (
        "encoding/hex"
        "crypto/sha256"

        blst "github.com/supranational/blst/bindings/go"
)

type blstSignature = blst.P2Affine
var dst = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")

func hashToG2(msg []byte, preHash bool) *blst.P2 {
        if preHash {
                sum := sha256.Sum256(msg)
                msg = sum[:]
        }

        k := blst.HashToG2(msg[:], dst, nil)
        return k
}

func main() {
        msg, err := hex.DecodeString("973153f86ec2da1748e63f0cf85b89835b42f8ee8018c549868a1308a19f6ca3")
        if err != nil {
                panic(err)
        }
        k := hashToG2(msg, false)
        k.Print("preHash: false")

        msg = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
        k = hashToG2(msg, true)
        k.Print("preHash: true")
}
```

The `hashToG2` functions, when called with its second argument as `true`, mimics the behavior of CometBFT `Sign` function, by pre-hashing in case of input longer than 32 bytes. The two messages above, clearly different, will be hashed to the same point on the curve, as it can be seen by running the program:

```
preHash: false:
preHash: false:
  x:
    0 = 0680ebb179b9625a39c1baa77435958544b4922b68d2003362bf4f41b1a8bcfd6c987e34e4f11a0bdf125fcc8c344dee
    1 = 0298d72dc776c151ce9e235900a49e848da449c00fc021842bfbfdc596b02b2ad2a7015fd872c8edad83584296cf870f
  y:
    0 = 01acdb1e11c4734fc5e919ea1476e08fac271be2c52cc06572bc151c027629d9e01464556f3dccfe2c65a4ce40ad5f1b
    1 = 0d3448598e3f1f2d12187670fabc472df6d020c53d01c0e3828f1ebbe61761c22cda3f78c597cad270c9f75fda2bab01
preHash: true:
preHash: true:
  x:
    0 = 0680ebb179b9625a39c1baa77435958544b4922b68d2003362bf4f41b1a8bcfd6c987e34e4f11a0bdf125fcc8c344dee
    1 = 0298d72dc776c151ce9e235900a49e848da449c00fc021842bfbfdc596b02b2ad2a7015fd872c8edad83584296cf870f
  y:
    0 = 01acdb1e11c4734fc5e919ea1476e08fac271be2c52cc06572bc151c027629d9e01464556f3dccfe2c65a4ce40ad5f1b
    1 = 0d3448598e3f1f2d12187670fabc472df6d020c53d01c0e3828f1ebbe61761c22cda3f78c597cad270c9f75fda2bab01
```

The first message is the sha256 digest of the second one, but from the point of view of the signing application, they hash to the same point and will hence produce the same signature under the same key.

## Details

We use Ethereum Beacon Chain test vectors for BLS12-381 at https://github.com/ethereum/bls12-381-tests .  The code below shows two different encodings to G2, without and with pre-hashing, respectively: (the domain separation tag is the same as the one used in the test vectors, see https://github.com/ethereum/bls12-381-tests/blob/006855c56cb6491ee19b4aedfddb806aaeacb1db/main.py#L103)

```go
package main

import (
        "crypto/sha256"

        blst "github.com/supranational/blst/bindings/go"
)

type blstSignature = blst.P2Affine
var dst = []byte("QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_")

func hashToG2(msg []byte, preHash bool) *blst.P2 {
        if preHash {
                sum := sha256.Sum256(msg)
                msg = sum[:]
        }

        k := blst.HashToG2(msg[:], dst, nil)
        return k
}

func main() {
        msg := []byte("abcdef0123456789")
        k := hashToG2(msg, false)
        k.Print("preHash: false")

        k = hashToG2(msg, true)
        k.Print("preHash: true")
}
```

The message `abcdef0123456789` is from vector `hash_to_G2/hash_to_G2__c938b486cf69e8f7.json`, for which the following point are expected (G2 is over a 2-extension field, whence the two components for each coordinate):

```
x[0] = 0x121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0
x[1] = 0x190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c
y[0] = 0x05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8
y[1] = 0x0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be
```

Running the code above results in only the first case matching the expected point, that is, the test vector is satisfied only when no pre-hashing is introduced in the scheme:

```
preHash: false:
preHash: false:
  x:
    0 = 121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0
    1 = 190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c
  cy:
    0 = 05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8
    1 = 0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be
preHash: true:
preHash: true:
  x:
    0 = 15a4df2e7f48c9a668610e039c4cace5dc4b9c65d1f726b13a96fb68c0297480083264af290352c1b84f5e786a947a93
    1 = 0caf83aabb0895ead34edfe8d798f573e7829f35e3325f0aca78b52206d51018cb9a82cbac040a51cb9ca6eab717e9b3
  y:
    0 = 10729eaf67e498f91eccebcb139c058fc035af9920d33a3d67b22317bbae697847ea82f68f96e005d205b90c5950c4b8
    1 = 11dad0dca4707a0f40e42e9f59f0a78a2d0a18df5cae2f6baa65a5db581d2ba2ae947a6d30bd04bbe1d4588981b534ad
```

## Impact

Different objects yield the same signature under the same key, affecting the second-preimage resistance of the signature scheme, (indirectly) borrowed from the hash function.

## Fix

https://github.com/cometbft/cometbft/pull/4116
