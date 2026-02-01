import {
    createCipheriv,
    createDecipheriv,
    createHmac,
    randomBytes,
    timingSafeEqual,
} from "node:crypto";
import { Buffer } from "node:buffer";

/**
 * Fernet is a symmetric encryption method that makes sure that the message
 * encrypted cannot be manipulated/read without the key.
 * 
 * Spec: https://github.com/fernet/spec/blob/master/Spec.md
 */
export class Fernet {
    private signingKey: Buffer;
    private encryptionKey: Buffer;

    /**
     * @param key 32-byte URL-safe base64-encoded key
     */
    constructor(key: string) {
        if (!key) {
            throw new Error("Key is required");
        }

        // Decode key. Support both standard and url-safe base64, 
        // but we strictly expect 32 bytes decoded.
        // We treat incoming key as potential base64url so we normalizing it just in case,
        // although standard base64 decoding usually handles -_ if mapped, but Node's 'base64'
        // is strict about +/. Let's accept URL-safe.
        const decodedKey = this.fromBase64Url(key);

        if (decodedKey.length !== 32) {
            throw new Error("Fernet key must be 32 bytes (when decoded).");
        }

        // Split key: first 16 bytes = signing, last 16 bytes = encryption
        this.signingKey = decodedKey.subarray(0, 16);
        this.encryptionKey = decodedKey.subarray(16);
    }

    /**
     * Encrypts a message into a Fernet token.
     * @param message The message Buffer to encrypt.
     * @returns URL-safe Base64 encoded Fernet token string.
     */
    public encrypt(message: Buffer): string {
        const version = Buffer.from([0x80]);
        // Timestamp: 64-bit big-endian unsigned integer
        const time = BigInt(Math.floor(Date.now() / 1000));
        const timestamp = Buffer.alloc(8);
        timestamp.writeBigUInt64BE(time);

        const iv = randomBytes(16);

        // Encrypt ciphertext
        const cipher = createCipheriv("aes-128-cbc", this.encryptionKey, iv);
        // Node.js handles PKCS7 padding by default (autoPadding: true)
        const ciphertext = Buffer.concat([cipher.update(message), cipher.final()]);

        // Basic Parts: Version + Timestamp + IV + Ciphertext
        const basicParts = Buffer.concat([version, timestamp, iv, ciphertext]);

        // HMAC verification
        const hmac = createHmac("sha256", this.signingKey);
        hmac.update(basicParts);
        const signature = hmac.digest();

        // Final token: Basic Parts + HMAC
        const token = Buffer.concat([basicParts, signature]);

        // Encode as URL-safe Base64 with padding preserved
        return this.toBase64Url(token);
    }

    /**
     * Decrypts a Fernet token.
     * @param token The Fernet token string.
     * @param ttl (Optional) Time-to-live in seconds.
     * @returns The decrypted message Buffer.
     */
    public decrypt(token: string, ttl?: number): Buffer {
        if (!token) throw new Error("Token is required");

        // Decode
        const decodedToken = this.fromBase64Url(token);

        // Minimum length check
        // Version(1) + Timestamp(8) + IV(16) + HMAC(32) = 57 bytes (empty ciphertext possible? aes block is 16. padded empty is 16. so min ciphertext is 16. Total 73? 
        // Actually PKCS7 padding of empty string adds 16 bytes (one block of 16s). 
        // So min length likely 73. 
        // But spec says "If the decrypted data is not valid ...", let's stick to structural min first.
        // 1+8+16+32 = 57 overhead.
        if (decodedToken.length < 57) {
            throw new Error("Invalid Token: too short");
        }

        const version = decodedToken[0];
        if (version !== 0x80) {
            throw new Error("Invalid version");
        }

        const timestampBuf = decodedToken.subarray(1, 9);
        const iv = decodedToken.subarray(9, 25);
        const ciphertext = decodedToken.subarray(25, decodedToken.length - 32);
        const receivedHmac = decodedToken.subarray(decodedToken.length - 32);

        // Hmac Calculation
        const dataToSign = decodedToken.subarray(0, decodedToken.length - 32);
        const hmac = createHmac("sha256", this.signingKey);
        hmac.update(dataToSign);
        const computedHmac = hmac.digest();

        // Constant time check
        if (!timingSafeEqual(receivedHmac, computedHmac)) {
            throw new Error("Invalid Token: HMAC mismatch");
        }

        // TTL validaton
        const tokenTime = timestampBuf.readBigUInt64BE();
        const now = BigInt(Math.floor(Date.now() / 1000));

        // Clock skew check (60 seconds into future allowed)
        if (tokenTime > now + 60n) {
            throw new Error("Invalid Token: Timestamp in future");
        }

        // Expiration check
        if (ttl !== undefined && ttl !== null) {
            if (tokenTime + BigInt(ttl) < now) {
                throw new Error("Invalid Token: TTL expired");
            }
        }

        // Decrypt
        const decipher = createDecipheriv("aes-128-cbc", this.encryptionKey, iv);
        try {
            const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            return plain;
        } catch (e) {
            throw new Error("Invalid Token: Decryption failed or bad padding");
        }
    }

    // Helper for URL-safe Base64 preserving padding
    private toBase64Url(b: Buffer): string {
        return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
    }

    private fromBase64Url(s: string): Buffer {
        return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    }
}
