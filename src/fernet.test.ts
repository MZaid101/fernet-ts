import { describe, it, expect } from 'vitest';
import { Fernet } from './fernet.js';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';

describe('Fernet', () => {
    // Generate a valid 32-byte key for testing
    // 32 bytes in base64url. 
    // We can use randomBytes(32).toString('base64')... replace...
    const generateKey = () => randomBytes(32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
    const secret = generateKey();
    const f = new Fernet(secret);

    it('roundtrips a simple string', () => {
        const original = "Hello World";
        const token = f.encrypt(Buffer.from(original));
        const decrypted = f.decrypt(token);
        expect(decrypted.toString('utf-8')).toBe(original);
    });

    it('roundtrips binary data', () => {
        const original = randomBytes(128); // 128 bytes of random data
        const token = f.encrypt(original);
        const decrypted = f.decrypt(token);
        expect(decrypted.equals(original)).toBe(true);
    });

    it('roundtrips empty string', () => {
        const original = Buffer.alloc(0);
        const token = f.encrypt(original);
        const decrypted = f.decrypt(token);
        expect(decrypted.length).toBe(0);
    });

    it('rejects tampered token (HMAC mismatch)', () => {
        const token = f.encrypt(Buffer.from("secret"));
        const rawToken = Buffer.from(token.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

        // Flip the last byte (part of HMAC)
        rawToken[rawToken.length - 1] ^= 1;

        const badToken = rawToken.toString('base64').replace(/\+/g, '-').replace(/\//g, '_');

        expect(() => f.decrypt(badToken)).toThrow(/HMAC mismatch/);
    });

    it('rejects tampered token (Ciphertext modification)', () => {
        const token = f.encrypt(Buffer.from("secret message"));
        const rawToken = Buffer.from(token.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

        // Ciphertext is between IV (byte 25) and HMAC (last 32)
        // Let's modify a byte in the middle
        const mid = Math.floor(rawToken.length / 2);
        rawToken[mid] ^= 1;

        const badToken = rawToken.toString('base64').replace(/\+/g, '-').replace(/\//g, '_');

        // HMAC should catch this before AES even tries
        expect(() => f.decrypt(badToken)).toThrow(/HMAC mismatch/);
    });

    it('rejects invalid version', () => {
        const token = f.encrypt(Buffer.from("test"));
        const rawToken = Buffer.from(token.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

        // Set version (byte 0) to 0x81
        rawToken[0] = 0x81;

        // We must re-sign this if we want to reach version check? 
        // No, Fernet decrypt checks version *before* HMAC? 
        // Spec: "3. Verify the version byte..." -> "4. Verify the HMAC..."
        // So it should throw "Invalid version" *before* "HMAC mismatch".
        // HOWEVER, to be robust, let's just see what happens.

        const badToken = rawToken.toString('base64').replace(/\+/g, '-').replace(/\//g, '_');

        // Since we modified data, HMAC is also wrong. 
        // If implementation checks version first, we get "Invalid version".
        // If it checks HMAC first (security best practice sometimes?), we get HMAC mismatch.
        // My implementation checks Version FIRST.

        expect(() => f.decrypt(badToken)).toThrow(/Invalid version/);
    });

    it('rejects expired token', async () => {
        const token = f.encrypt(Buffer.from("test"));
        // Wait 2 seconds (not really feasible for unit test to wait 60s)
        // We can manually craft an old token.

        // Mocking time or crafting token manually is better.
        // Let's craft a token with old timestamp.
        const now = Math.floor(Date.now() / 1000);
        const oldTime = BigInt(now - 100); // 100 seconds ago

        // We need access to internals or manual construction to sign it correctly
        // Since Fernet logic is encapsulated, let's "mock" the construction by just using another instance?
        // No, we can't easily sign it without the key splitting logic which is private.
        // But we are testing the class. 
        // We can create a subclass or expose helpers for testing, but that's messy.
        // Actually, we can just use the public encryption, then modify the timestamp, AND re-sign it?
        // But we need the signing key.
        // Okay, let's just assume we can't easily test TTL without mocking Date or exposing keys.
        // I'll skip complex TTL test for now OR rely on the fact that I can't easily forge a valid signed old token without re-implementing logic in test.
        // But wait, I have the key 'secret'!

        // I can rebuild the token manually in test.
        const decodedKey = Buffer.from(secret.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        const signingKey = decodedKey.subarray(0, 16);
        const encryptionKey = decodedKey.subarray(16);

        const version = Buffer.from([0x80]);
        const timestamp = Buffer.alloc(8);
        timestamp.writeBigUInt64BE(oldTime);
        const iv = randomBytes(16);
        const cipher = await import('node:crypto').then(c => c.createCipheriv('aes-128-cbc', encryptionKey, iv));
        const ciphertext = Buffer.concat([cipher.update("test"), cipher.final()]);
        const basicParts = Buffer.concat([version, timestamp, iv, ciphertext]);

        const hmac = await import('node:crypto').then(c => c.createHmac('sha256', signingKey));
        hmac.update(basicParts);
        const signature = hmac.digest();

        const oldToken = Buffer.concat([basicParts, signature]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_');

        expect(() => f.decrypt(oldToken, 60)).toThrow(/TTL expired/);
    });

    // TODO: Add Python compatibility test with known token provided by user
});
