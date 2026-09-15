# Merkle tree test vectors

`transparency-dev.json` holds values copied unchanged from
<https://github.com/transparency-dev/merkle/blob/main/testonly/constants.go>
(Copyright 2019 Google LLC, Apache License 2.0), which implements the RFC 6962
tree hashing that RFC 9162 keeps.

| Field | Meaning |
|---|---|
| `leaf_inputs` | Eight leaf inputs, hex |
| `leaf_hashes` | `SHA-256(0x00 || input)` for each leaf (level 0 of `NodeHashes`) |
| `root_hashes` | Tree root for sizes 1 through 8 |
| `empty_root` | Root of the empty tree, `SHA-256("")` |

The values were extracted from the Go source by script, not retyped.
