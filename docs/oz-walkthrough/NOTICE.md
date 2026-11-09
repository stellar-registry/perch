# One payment, two rules: provenance and notices

`index.html` is a self-contained, offline walkthrough that runs one task
under an OpenZeppelin smart account with oz-policy-builder's rule and under
Perch, in soroban-sim in the browser. It is embedded here unchanged
(SHA-256 `45f4759b3271d261de60b7e782cd81688317118617e0bbfeaee944374ec78656`)
and linked from the Perch paper's comparison section.

The page lists every source revision and contract hash it runs in its
"Sources and hashes" section, and carries its own build sources ("Download
the build sources"; `BUILD.md` inside gives the rebuild steps).

## Third-party software in the page

The page contains WebAssembly built from the following projects, at the
revisions the page lists.

| Project | Revision | License |
| --- | --- | --- |
| untangledfinance/oz-policy-builder (policy interpreter, policy-synth output) | `43b13ed1d9c6662afd74f446006e69bfcf21259b` | MIT (below) |
| OpenZeppelin/stellar-contracts (smart account, `spending_limit`) | `ddc327eb92d63709436da3a8455f641c2d5476c5` (v0.8.0) | MIT (below) |
| theahaco/soroban-sim | `d02938430f0ac41f34e5e3e4c8c48d85b871bd68` | Apache-2.0 |
| stellar/rs-soroban-env (soroban-env-host 29.0.2) | crates.io release | Apache-2.0 |
| bitswell-hq/stellar-registry__perch | `f0275f41c5ab47c903bbfe9986b4bf3239c01b11` | Apache-2.0 |
| bitswell/soroban-rule-core | `cbabe594ae2df408991e825e56ddd618ea29541b` | Apache-2.0 |

The Apache-2.0 text is in this repository's `LICENSE`.

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
