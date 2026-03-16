/**
 * PQ Secure Vault — Pure JS/WASM implementation.
 *
 * Same cryptographic stack as the Rust version, using battle-tested npm packages:
 *
 *   hash-wasm        → Argon2id  (pre-built WASM, JS-managed memory — no OOB errors)
 *   @noble/ciphers   → ChaCha20-Poly1305  (audited, constant-time)
 *   @noble/hashes    → BLAKE3, HKDF-SHA512  (audited)
 *
 * Dependencies:
 *   npm install hash-wasm @noble/ciphers @noble/hashes
 *
 * Drop-in replacement for pq-secure-vault.js — identical API.
 *
 * @version 2.0.0
 * @module PQSecureVault
 */

import { argon2id } from 'hash-wasm';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

// ============================================
// Constants
// ============================================

/** Default Argon2id memory cost: 19 MiB (KiB) — OWASP minimum */
export const DEFAULT_MEMORY_KIB = 19456;

/** Default Argon2id iterations */
export const DEFAULT_ITERATIONS = 2;

/** Low-memory profile: 9 MiB, 3 iterations */
export const LOW_MEMORY_KIB = 9216;
export const LOW_MEMORY_ITERATIONS = 3;

/** Vault format version */
export const VAULT_VERSION = 2;

/** HKDF purpose strings for domain separation */
const PURPOSE_ENCRYPT = 'pixa-vault-encrypt-v1';
const PURPOSE_VERIFY  = 'pixa-vault-verify-v1';
const PURPOSE_SESSION = 'pixa-vault-session-v1';

/** ChaCha20-Poly1305 nonce size in bytes */
const NONCE_SIZE = 12;

// ============================================
// Internal helpers
// ============================================

/**
 * Derive 32-byte master key via Argon2id.
 * hash-wasm manages WASM memory from JS — no OOB errors regardless of memorySize.
 */
async function argon2idDerive(pin, saltBytes, memoryKib, iterations) {
    const pinBytes = typeof pin === 'string' ? utf8ToBytes(pin) : pin;
    const hash = await argon2id({
        password: pinBytes,
        salt: saltBytes,
        parallelism: 1,
        iterations: iterations,
        memorySize: memoryKib,
        hashLength: 32,
        outputType: 'binary',
    });
    return new Uint8Array(hash);
}

/**
 * Derive a sub-key via HKDF-SHA512 with a purpose string.
 */
function deriveSubkey(masterKey, purpose, length = 32) {
    const info = typeof purpose === 'string' ? utf8ToBytes(purpose) : purpose;
    return hkdf(sha3_512, masterKey, undefined, info, length);
}

/**
 * Encrypt with ChaCha20-Poly1305 + optional AAD.
 * Returns: nonce(12) || ciphertext || tag(16)
 */
function chachaEncrypt(key, plaintext, aad) {
    const nonce = randomBytes(NONCE_SIZE);
    const cipher = chacha20poly1305(key, nonce, aad);
    const ct = cipher.encrypt(plaintext);
    return concatBytes(nonce, ct);
}

/**
 * Decrypt with ChaCha20-Poly1305 + optional AAD.
 */
function chachaDecrypt(key, data, aad) {
    if (data.length < NONCE_SIZE + 16) throw new Error('Invalid ciphertext: too short');
    const nonce = data.slice(0, NONCE_SIZE);
    const ct = data.slice(NONCE_SIZE);
    const cipher = chacha20poly1305(key, nonce, aad);
    return cipher.decrypt(ct);
}

function toBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

function fromBase64(str) {
    return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
}

// ============================================
// Initialization (no-op — hash-wasm self-inits)
// ============================================

/**
 * Initialize the vault module.
 * With hash-wasm this is a no-op — the WASM modules are loaded lazily
 * on first use. Kept for API compatibility with the Rust version.
 *
 * @param {any} [_initFn] - Ignored (compatibility shim)
 * @returns {Promise<void>}
 */
export async function initPQVault(_initFn) {
    // hash-wasm auto-initializes on first call.
    // Run a tiny derivation to warm up the WASM module.
    try {
        await argon2id({
            password: new Uint8Array([0]),
            salt: new Uint8Array(16),
            parallelism: 1,
            iterations: 1,
            memorySize: 256,
            hashLength: 8,
            outputType: 'binary',
        });
    } catch (e) {
        throw new Error('[PQSecureVault] Argon2id WASM init failed: ' + (e.message || e));
    }
}

// ============================================
// PQSecureVault Class
// ============================================

export class PQSecureVault {
    /**
     * @param {object} [options]
     * @param {number} [options.memoryKib=19456]  Argon2id memory in KiB
     * @param {number} [options.iterations=2]     Argon2id time cost
     */
    constructor(options = {}) {
        this.memoryKib = options.memoryKib || DEFAULT_MEMORY_KIB;
        this.iterations = options.iterations || DEFAULT_ITERATIONS;

        /** @private Cached encryption key (Uint8Array). Zeroed on lock(). */
        this._cachedEncKey = null;
        /** @private Cached salt hex */
        this._cachedSalt = null;
    }

    // ── Salt ─────────────────────────────────────────

    /**
     * Generate a CSPRNG salt.
     * @param {number} [byteLength=32]
     * @returns {string} Hex-encoded salt
     */
    generateSalt(byteLength = 32) {
        return bytesToHex(randomBytes(byteLength));
    }

    // ── Key derivation ───────────────────────────────

    /**
     * Derive the encryption key from PIN + salt.
     * Pipeline: PIN → Argon2id(salt) → HKDF("encrypt") → 256-bit key.
     *
     * @param {string} pin
     * @param {string} salt - Hex-encoded salt
     * @returns {Promise<string>} Hex-encoded 32-byte key
     */
    async deriveKey(pin, salt) {
        const saltBytes = hexToBytes(salt);
        const master = await argon2idDerive(pin, saltBytes, this.memoryKib, this.iterations);
        const encKey = deriveSubkey(master, PURPOSE_ENCRYPT, 32);
        // Zeroize master
        master.fill(0);

        this._cachedEncKey = encKey;
        this._cachedSalt = salt;
        return bytesToHex(encKey);
    }

    /**
     * Derive key as ArrayBuffer (Web Crypto compatible).
     * @param {string} pin
     * @param {string} salt
     * @returns {Promise<ArrayBuffer>}
     */
    async deriveKeyAsArrayBuffer(pin, salt) {
        const hexKey = await this.deriveKey(pin, salt);
        return hexToBytes(hexKey).buffer;
    }

    // ── PIN verification ─────────────────────────────

    /**
     * Generate a PIN verification hash.
     * Pipeline: PIN → Argon2id → HKDF("verify") → BLAKE3.
     * Safe to store in plaintext — cannot derive encryption key.
     *
     * @param {string} pin
     * @param {string} salt
     * @returns {Promise<string>} Hex-encoded BLAKE3 hash (64 chars)
     */
    async generateVerifyHash(pin, salt) {
        const saltBytes = hexToBytes(salt);
        const master = await argon2idDerive(pin, saltBytes, this.memoryKib, this.iterations);
        const verifyKey = deriveSubkey(master, PURPOSE_VERIFY, 32);
        master.fill(0);
        const hash = blake3(verifyKey);
        verifyKey.fill(0);
        return bytesToHex(hash);
    }

    /**
     * Verify a PIN against a stored hash.
     * @param {string} pin
     * @param {string} salt
     * @param {string} storedHash
     * @returns {Promise<boolean>}
     */
    async verifyPin(pin, salt, storedHash) {
        const computed = await this.generateVerifyHash(pin, salt);
        // Constant-time comparison
        if (computed.length !== storedHash.length) return false;
        let diff = 0;
        for (let i = 0; i < computed.length; i++) {
            diff |= computed.charCodeAt(i) ^ storedHash.charCodeAt(i);
        }
        return diff === 0;
    }

    // ── Low-level encrypt / decrypt ──────────────────

    /**
     * Encrypt a string with a pre-derived key.
     * @param {string} keyHex - Hex-encoded 32-byte key
     * @param {string} plaintext
     * @param {string} [aad]
     * @returns {string} Base64-encoded ciphertext
     */
    encrypt(keyHex, plaintext, aad) {
        const key = hexToBytes(keyHex);
        const pt = utf8ToBytes(plaintext);
        const aadBytes = aad ? utf8ToBytes(aad) : undefined;
        const ct = chachaEncrypt(key, pt, aadBytes);
        return toBase64(ct);
    }

    /**
     * Decrypt a base64 ciphertext.
     * @param {string} keyHex
     * @param {string} ciphertextB64
     * @param {string} [aad]
     * @returns {string} Plaintext
     */
    decrypt(keyHex, ciphertextB64, aad) {
        const key = hexToBytes(keyHex);
        const data = fromBase64(ciphertextB64);
        const aadBytes = aad ? utf8ToBytes(aad) : undefined;
        const pt = chachaDecrypt(key, data, aadBytes);
        return new TextDecoder().decode(pt);
    }

    // ── High-level vault operations ──────────────────

    /**
     * Seal a single secret.
     * @param {string} pin
     * @param {string} salt
     * @param {string} account
     * @param {string} plaintext
     * @returns {Promise<object>} SealedRecord
     */
    async sealSecret(pin, salt, account, plaintext) {
        const keyHex = await this.deriveKey(pin, salt);
        const ct = this.encrypt(keyHex, plaintext, account);
        const fingerprint = bytesToHex(blake3(hexToBytes(keyHex)));
        return {
            version: VAULT_VERSION,
            ciphertext: ct,
            aad_account: account,
            key_fingerprint: fingerprint,
            created_at: Date.now(),
        };
    }

    /**
     * Unseal a single secret.
     * @param {string} pin
     * @param {string} salt
     * @param {object} sealedRecord
     * @returns {Promise<string>} Plaintext
     */
    async unsealSecret(pin, salt, sealedRecord) {
        const keyHex = await this.deriveKey(pin, salt);
        return this.decrypt(keyHex, sealedRecord.ciphertext, sealedRecord.aad_account);
    }

    /**
     * Seal multiple keys (posting, active, memo, owner).
     * Each key type gets AAD = `account:type`.
     *
     * @param {string} pin
     * @param {string} salt
     * @param {string} account
     * @param {object} keys - { posting: 'WIF', active: 'WIF', ... }
     * @returns {Promise<string>} Sealed JSON blob
     */
    async sealKeys(pin, salt, account, keys) {
        const keyHex = await this.deriveKey(pin, salt);
        const fingerprint = bytesToHex(blake3(hexToBytes(keyHex)));
        const now = Date.now();
        const sealed = {};

        for (const [type, value] of Object.entries(keys)) {
            const aad = `${account}:${type}`;
            sealed[type] = {
                version: VAULT_VERSION,
                ciphertext: this.encrypt(keyHex, value, aad),
                aad_account: aad,
                key_fingerprint: fingerprint,
                created_at: now,
            };
        }

        return JSON.stringify(sealed);
    }

    /**
     * Unseal multiple keys from a sealed JSON blob.
     * @param {string} pin
     * @param {string} salt
     * @param {string} sealedJson
     * @returns {Promise<object>} { posting: 'WIF', active: 'WIF', ... }
     */
    async unsealKeys(pin, salt, sealedJson) {
        const keyHex = await this.deriveKey(pin, salt);
        const sealed = JSON.parse(sealedJson);
        const result = {};

        for (const [type, record] of Object.entries(sealed)) {
            result[type] = this.decrypt(keyHex, record.ciphertext, record.aad_account);
        }

        return result;
    }

    // ── Session management ───────────────────────────

    /**
     * Derive + cache the encryption key for fast repeated operations.
     * @param {string} pin
     * @param {string} salt
     * @returns {Promise<string>} Cached key hex
     */
    async unlockSession(pin, salt) {
        const keyHex = await this.deriveKey(pin, salt);
        this._cachedEncKey = hexToBytes(keyHex);
        this._cachedSalt = salt;
        return keyHex;
    }

    isUnlocked() {
        return this._cachedEncKey !== null;
    }

    sessionEncrypt(plaintext, aad) {
        if (!this._cachedEncKey) throw new Error('Vault not unlocked. Call unlockSession() first.');
        return this.encrypt(bytesToHex(this._cachedEncKey), plaintext, aad);
    }

    sessionDecrypt(ciphertextB64, aad) {
        if (!this._cachedEncKey) throw new Error('Vault not unlocked. Call unlockSession() first.');
        return this.decrypt(bytesToHex(this._cachedEncKey), ciphertextB64, aad);
    }

    lock() {
        if (this._cachedEncKey) {
            this._cachedEncKey.fill(0);
            this._cachedEncKey = null;
        }
        this._cachedSalt = null;
    }

    // ── Utility ──────────────────────────────────────

    getInfo() {
        return {
            version: VAULT_VERSION,
            kdf: 'argon2id',
            cipher: 'chacha20-poly1305',
            hash: 'blake3',
            domain_sep: 'hkdf-sha3-512',
            default_memory_kib: DEFAULT_MEMORY_KIB,
            default_iterations: DEFAULT_ITERATIONS,
            key_size_bits: 256,
            nonce_size_bits: 96,
            tag_size_bits: 128,
            runtime: 'hash-wasm + @noble/ciphers',
        };
    }

    blake3(data) {
        const bytes = typeof data === 'string' ? utf8ToBytes(data) : data;
        return bytesToHex(blake3(bytes));
    }

    /**
     * Auto-tune Argon2id params for this device.
     * @param {number} [targetMs=1500]
     * @returns {Promise<{ memoryKib, iterations, label, measuredMs }>}
     */
    async autoTuneParams(targetMs = 1500) {
        const profiles = [
            { memoryKib: 46080, iterations: 2, label: 'high' },
            { memoryKib: 19456, iterations: 2, label: 'standard' },
            { memoryKib: 9216,  iterations: 3, label: 'low' },
        ];

        const testSalt = randomBytes(16);

        for (const profile of profiles) {
            try {
                const start = performance.now();
                await argon2idDerive('bench1', testSalt, profile.memoryKib, profile.iterations);
                const elapsed = performance.now() - start;

                if (elapsed <= targetMs * 1.5) {
                    this.memoryKib = profile.memoryKib;
                    this.iterations = profile.iterations;
                    return { ...profile, measuredMs: Math.round(elapsed) };
                }
            } catch (e) {
                console.warn(`[PQSecureVault] autoTune: ${profile.label} failed:`, e.message || e);
                continue;
            }
        }

        const fallback = profiles[profiles.length - 1];
        this.memoryKib = fallback.memoryKib;
        this.iterations = fallback.iterations;
        return { ...fallback, measuredMs: -1 };
    }
}

export default PQSecureVault;