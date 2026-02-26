import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { encrypt, decrypt } from '../src/crypto/encryption.js';
import { deriveKey, generateSalt } from '../src/crypto/keyDerivation.js';

// ---------------------------------------------------------------------------
// AES-256-GCM Encryption
// ---------------------------------------------------------------------------
describe('encrypt / decrypt', () => {
  const key = randomBytes(32);

  it('encrypt then decrypt returns the original data', () => {
    const plaintext = 'sk-abc123-my-super-secret-api-key';

    const { ciphertext, iv, tag } = encrypt(plaintext, key);
    const result = decrypt(ciphertext, key, iv, tag);

    expect(result).toBe(plaintext);
  });

  it('handles empty string', () => {
    const { ciphertext, iv, tag } = encrypt('', key);
    const result = decrypt(ciphertext, key, iv, tag);

    expect(result).toBe('');
  });

  it('handles unicode and multi-byte characters', () => {
    const plaintext = '🔐 Lockbox — encrypted vault 日本語';

    const { ciphertext, iv, tag } = encrypt(plaintext, key);
    const result = decrypt(ciphertext, key, iv, tag);

    expect(result).toBe(plaintext);
  });

  it('wrong key fails to decrypt', () => {
    const plaintext = 'sk-abc123-my-super-secret-api-key';
    const wrongKey = randomBytes(32);

    const { ciphertext, iv, tag } = encrypt(plaintext, key);

    expect(() => decrypt(ciphertext, wrongKey, iv, tag)).toThrow();
  });

  it('tampered ciphertext fails to decrypt', () => {
    const plaintext = 'sk-abc123-my-super-secret-api-key';

    const { ciphertext, iv, tag } = encrypt(plaintext, key);

    // Flip a byte in the ciphertext
    ciphertext[0] ^= 0xff;

    expect(() => decrypt(ciphertext, key, iv, tag)).toThrow();
  });

  it('tampered tag fails to decrypt', () => {
    const plaintext = 'sk-abc123-my-super-secret-api-key';

    const { ciphertext, iv, tag } = encrypt(plaintext, key);

    // Flip a byte in the auth tag
    tag[0] ^= 0xff;

    expect(() => decrypt(ciphertext, key, iv, tag)).toThrow();
  });

  it('different encryptions of same data produce different ciphertext', () => {
    const plaintext = 'same-data-encrypted-twice';

    const result1 = encrypt(plaintext, key);
    const result2 = encrypt(plaintext, key);

    // IVs must differ (random)
    expect(result1.iv.equals(result2.iv)).toBe(false);

    // Ciphertexts must differ (because IVs differ)
    expect(result1.ciphertext.equals(result2.ciphertext)).toBe(false);

    // Both must still decrypt correctly
    expect(decrypt(result1.ciphertext, key, result1.iv, result1.tag)).toBe(plaintext);
    expect(decrypt(result2.ciphertext, key, result2.iv, result2.tag)).toBe(plaintext);
  });

  it('rejects key that is not 32 bytes', () => {
    const shortKey = randomBytes(16);

    expect(() => encrypt('data', shortKey)).toThrow('32 bytes');
    expect(() => decrypt(Buffer.from('x'), shortKey, randomBytes(12), randomBytes(16))).toThrow('32 bytes');
  });
});

// ---------------------------------------------------------------------------
// Argon2id Key Derivation
// ---------------------------------------------------------------------------
describe('deriveKey / generateSalt', () => {
  it('generateSalt returns a 16-byte buffer', () => {
    const salt = generateSalt();

    expect(Buffer.isBuffer(salt)).toBe(true);
    expect(salt.length).toBe(16);
  });

  it('generateSalt produces unique salts', () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();

    expect(salt1.equals(salt2)).toBe(false);
  });

  it('same password + salt produces the same key', async () => {
    const password = 'my-master-password';
    const salt = generateSalt();

    const key1 = await deriveKey(password, salt);
    const key2 = await deriveKey(password, salt);

    expect(key1.equals(key2)).toBe(true);
  });

  it('derived key is 32 bytes', async () => {
    const key = await deriveKey('password', generateSalt());

    expect(Buffer.isBuffer(key)).toBe(true);
    expect(key.length).toBe(32);
  });

  it('different passwords produce different keys', async () => {
    const salt = generateSalt();

    const key1 = await deriveKey('password-one', salt);
    const key2 = await deriveKey('password-two', salt);

    expect(key1.equals(key2)).toBe(false);
  });

  it('different salts produce different keys', async () => {
    const password = 'same-password';

    const key1 = await deriveKey(password, generateSalt());
    const key2 = await deriveKey(password, generateSalt());

    expect(key1.equals(key2)).toBe(false);
  });

  it('rejects salt that is not 16 bytes', async () => {
    const badSalt = randomBytes(8);

    await expect(deriveKey('password', badSalt)).rejects.toThrow('16 bytes');
  });
});

// ---------------------------------------------------------------------------
// Integration: derive key → encrypt → decrypt
// ---------------------------------------------------------------------------
describe('full round-trip: deriveKey → encrypt → decrypt', () => {
  it('derives a key and uses it to encrypt/decrypt', async () => {
    const password = 'hunter2';
    const salt = generateSalt();
    const plaintext = 'sk-live-1234567890abcdef';

    const key = await deriveKey(password, salt);
    const { ciphertext, iv, tag } = encrypt(plaintext, key);
    const result = decrypt(ciphertext, key, iv, tag);

    expect(result).toBe(plaintext);
  });

  it('wrong password cannot decrypt', async () => {
    const salt = generateSalt();
    const plaintext = 'sk-live-1234567890abcdef';

    const rightKey = await deriveKey('correct-password', salt);
    const wrongKey = await deriveKey('wrong-password', salt);

    const { ciphertext, iv, tag } = encrypt(plaintext, rightKey);

    expect(() => decrypt(ciphertext, wrongKey, iv, tag)).toThrow();
  });
});
