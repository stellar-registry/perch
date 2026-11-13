# OZ and Perch in soroban-sim: notices

`index.html` is a self-contained, offline page that runs an OpenZeppelin
smart account with an oz-policy-builder rule and `spending_limit`, and a
Perch account with one grant, side by side in soroban-sim in the browser. It
lists every source revision and contract hash it runs in its "Sources and
hashes" section, carries its own build sources ("Download the build sources";
`BUILD.md` inside gives the rebuild steps), and repeats these notices in its
"Third-party notices" section.

## Third-party software in the page

The page contains WebAssembly built from the following projects, at the
revisions listed. The reactor also links Rust crates from crates.io under
their own licenses (MIT or Apache-2.0); `Cargo.lock` in the build sources
lists them.

| Project | Revision | Used here | License |
| --- | --- | --- | --- |
| untangledfinance/oz-policy-builder | `43b13ed1d9c6662afd74f446006e69bfcf21259b` | policy interpreter (Wasm); the policy-synth output the page installs | MIT (below) |
| OpenZeppelin/stellar-contracts | `ddc327eb92d63709436da3a8455f641c2d5476c5` (v0.8.0) | multisig smart account and `spending_limit` (Wasm) | MIT (below) |
| theahaco/soroban-sim | `d02938430f0ac41f34e5e3e4c8c48d85b871bd68` | the simulator, in the reactor | Apache-2.0 |
| stellar/rs-soroban-env (soroban-env-host 29.0.2) | crates.io release | the Soroban host, in the reactor | Apache-2.0 |
| bitswell-hq/stellar-registry__perch | `0b3752d8a179a5952b05fbebd29131dbbf99fa80` | Perch account, document compiler, Ed25519 verifier (Wasm); the driver | Apache-2.0 |
| bitswell/soroban-rule-core | `a3c92ba074dcac4052727b7599e5fd8674af6c0a` | Perch's evaluator, linked into the account | MIT OR Apache-2.0, used under Apache-2.0 |

The Apache-2.0 text is in this repository's `LICENSE` and in the page.

### oz-policy-builder

```
MIT License

Copyright (c) 2026 Untangled Finance Limited

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### OpenZeppelin stellar-contracts

```
MIT License

Copyright (c) 2024 OpenZeppelin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
