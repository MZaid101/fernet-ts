# fernet-ts

A 100% Python-compatible Fernet encryption library for TypeScript/Node.js.

This library is designed to be bit-for-bit compatible with the [Python `cryptography` library](https://cryptography.io/en/latest/fernet/), allowing tokens generated in Python to be decrypted in Node.js and vice versa. It is built for security-critical applications requiring strict adherence to the [Fernet Spec](https://github.com/fernet/spec/blob/master/Spec.md).

## Features

- **Python Compatibility**: Verified interoperability with `cryptography.fernet`.
- **security**: Uses `AES-128-CBC`, `HMAC-SHA256`, and constant-time verification logic (`crypto.timingSafeEqual`) to prevent timing attacks.
- **BigInt Support**: Handles 64-bit Big-Endian timestamps correctly for long-term safety (Y2038 safe).
- **Url-Safe**: standard URL-safe Base64 encoding/decoding.
- **Zero Dependencies**: Built on native Node.js `crypto` module.

## Installation

```bash
npm install fernet-ts
```

> **Note**: This package is currently in your local workspace. To use it in another project, you can link it or publish it.

## Usage

### Key Generation

You can generate a valid key using the `crypto` module in Node.js:

```typescript
import { randomBytes } from 'node:crypto';

// Generate 32 bytes and encode as URL-safe Base64
const key = randomBytes(32).toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_');

console.log(key); // e.g. cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=
```

### Basic Encryption & Decryption

```typescript
import { Fernet } from './dist/fernet.js'; // Adjust path if using raw src

// Use a 32-byte URL-safe base64-encoded key
// You can generate one in Python using `Fernet.generate_key()`
const key = 'cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4='; 

const f = new Fernet(key);

// Encryption
const token = f.encrypt(Buffer.from('Sensitive Data'));
console.log('Token:', token);

// Decryption
const message = f.decrypt(token);
console.log('Decrypted:', message.toString());
```

### Implementing TTL (Time-To-Live)

You can enforce a maximum lifetime for tokens (in seconds). Tokens older than `ttl` will throw an error.

```typescript
try {
  // Fail if token is older than 60 seconds
  const message = f.decrypt(token, 60); 
} catch (err) {
  console.error('Token expired or invalid:', err.message);
}
```

## Running Tests

This project uses [Vitest](https://vitest.dev/).

```bash
npm test
```

### Cross-Language Compatibility

This library includes a Python script (`verify_compat.py`) and an integration test (`src/compat.test.ts`) that verifies real-time compatibility with Python's `cryptography` library.

To run these tests, ensure you have Python and `cryptography` installed:
```bash
pip install cryptography
npm test src/compat.test.ts
```


## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Zaid Aslam
