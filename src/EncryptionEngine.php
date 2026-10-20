<?php
/**
 * EncryptionEngine.php — "Encryption Engine: the mechanism that encodes and decodes data."
 *
 * This is the engine the rest of the project reuses. It uses AES-256-GCM,
 * which is what modern apps (HTTPS, WhatsApp, cloud storage) actually use.
 *
 * The encryption process in 3 steps, and where they happen below:
 *   1. Algorithm usage  -> self::CIPHER  ('aes-256-gcm')
 *   2. Key application  -> the $key argument (32 random bytes from KeyManager)
 *   3. Encoding         -> openssl_encrypt() mixes algorithm + key + data into ciphertext
 *
 * Why GCM? It is "authenticated encryption": besides hiding the data it also
 * produces a 16-byte TAG. If anyone changes even one bit of the ciphertext,
 * decryption fails instead of returning garbage. (That's the "integrity" goal.)
 */

declare(strict_types=1);

final class EncryptionEngine
{
    public const CIPHER   = 'aes-256-gcm'; // class constant (TS: static readonly CIPHER = ...)
    public const KEY_LEN  = 32;            // 256-bit key
    public const IV_LEN   = 12;            // 96-bit "nonce"/IV: random per message
    public const TAG_LEN  = 16;            // 128-bit authentication tag

    /**
     * Encrypt plaintext -> base64 string containing  IV + TAG + CIPHERTEXT.
     *
     * The IV (initialisation vector) is random every time, so encrypting the
     * same message twice gives DIFFERENT ciphertext. The IV isn't secret, so we
     * simply glue it to the front of the output so decrypt() can find it.
     *
     * $aad = "additional authenticated data": extra info that is NOT encrypted but
     * IS protected from tampering (used in the network-level demo for packet headers).
     */
    public static function encrypt(string $plaintext, string $key, string $aad = ''): string
    {
        self::checkKey($key);

        $iv  = random_bytes(self::IV_LEN);
        $tag = ''; // openssl_encrypt fills this in for us (passed "by reference")

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,   // give us raw bytes (we base64 the whole package ourselves)
            $iv,
            $tag,
            $aad,
            self::TAG_LEN
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed: ' . openssl_error_string());
        }

        // base64 turns binary bytes into safe text (JS: btoa / Buffer.toString('base64'))
        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Decrypt a package made by encrypt(). Throws if the key is wrong
     * or if the data was modified.
     */
    public static function decrypt(string $package, string $key, string $aad = ''): string
    {
        self::checkKey($key);

        $raw = base64_decode($package, true);
        if ($raw === false || strlen($raw) < self::IV_LEN + self::TAG_LEN) {
            throw new RuntimeException('That is not a valid ciphertext package.');
        }

        // Cut the package back into its three parts. substr(string, start, length) ~ JS .slice()
        $iv         = substr($raw, 0, self::IV_LEN);
        $tag        = substr($raw, self::IV_LEN, self::TAG_LEN);
        $ciphertext = substr($raw, self::IV_LEN + self::TAG_LEN);

        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);

        if ($plaintext === false) {
            throw new RuntimeException('Decryption failed — wrong key, or the ciphertext was tampered with.');
        }
        return $plaintext;
    }

    private static function checkKey(string $key): void
    {
        if (strlen($key) !== self::KEY_LEN) {
            throw new InvalidArgumentException('AES-256 needs a 32-byte key, got ' . strlen($key) . ' bytes.');
        }
    }
}
