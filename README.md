# wallet.wasm

WebAssembly bundle for Wallet

```bash
npm i @brumewallet/wallet.wasm
```

[**Node Package 📦**](https://www.npmjs.com/package/@brumewallet/wallet.wasm)

## Features
- Reproducible building
- Pre-bundled and streamed
- Zero-copy memory slices

## Bundles
- network.wasm
- base16.wasm
- base58.wasm
- base64.wasm
- ed25519.wasm
- x25519.wasm
- sha1.wasm
- sha3.wasm
- secp256k1.wasm
- ripemd.wasm
- chacha20poly1305.wasm

## Algorithms
- Network
- Base16
- Base58
- Base64
- Ed25519
- X25519
- SHA-1
- SHA-3
- Secp256k1
- Ripemd160
- ChaCha20-Poly1305

## Building

### Unreproducible building

You need to install [Rust](https://www.rust-lang.org/tools/install)

Then, install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

```bash
cargo install wasm-pack
```

Finally, do a clean install and build

```bash
npm ci && npm run build
```

### Reproducible building

You can build the exact same bytecode using Docker, just be sure you're on a `linux/amd64` host

```bash
docker compose up --build
```

Then check that all the files are the same using `npm diff`

```bash
npm diff
```

If the output is empty then the bytecode is the same as the one I commited

### Automated checks

Each time I release a new version on GitHub, the GitHub's CI clones the GitHub repository, reproduces the build, and throws an error if the NPM release is different. If a version is present on NPM but not on GitHub, do not use it!
