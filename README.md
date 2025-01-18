# nistkdf-800-108
A pure Node.js implementation of the [NISTKDF-800-108 Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf). Implementation is validated via [CAVP test vectors provided by NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-derivation).

## Installation
```sh
npm i nistkdf-800-108
```

## Usage
```js
import { counterKdf } from "nistkdf-800-108";

const key = Buffer.from("00112233445566778899001122334455", "hex");
const label = Buffer.from("some-label", "utf-8");
const context = Buffer.from("some-context", "utf-8");

const derivedKey = counterKdf(16, "sha256", key, label, context);
console.log("Derived key:", derivedKey);
```
