<?php
/**
 * KeyManager.php — "Key Manager: handles the generation and management of encryption keys."
 *
 * An encryption system has THREE parts:
 *   1. Data              -> whatever text/file you want to protect
 *   2. Encryption Engine -> EncryptionEngine.php (does the scrambling)
 *   3. Key Manager       -> THIS FILE (creates, stores and hands out keys)
 *
 * Keeping keys separate from the engine and the data is the "distributed setup"
 * idea: if one part is stolen, the attacker still lacks the others.
 *
 * Here keys are saved as files in your storage folder (storage/.../keys/). In real systems they'd live in a
 * dedicated service such as AWS KMS, Azure Key Vault, or a hardware security module (HSM).
 */

declare(strict_types=1);

final class KeyManager   // `final` = no other class may extend this one
{
    /**
     * Constructor "property promotion": writing `private string $dir` in the
     * constructor's parameter list declares AND assigns $this->dir in one go.
     * TS equivalent:  constructor(private dir: string) {}
     */
    public function __construct(private string $dir)
    {
        if (!is_dir($this->dir)) {
            mkdir($this->dir, 0700, true); // 0700 = only the owner can read the folder
        }
    }

    /**
     * Generate a brand-new random key.
     * random_bytes() uses the OS's secure random generator.
     * JS equivalent: crypto.getRandomValues(new Uint8Array(32))
     *
     * 32 bytes = 256 bits -> the key size for AES-256.
     */
    public static function generateKey(int $bytes = 32): string
    {
        return random_bytes($bytes);
    }

    /**
     * Turn a human password into a fixed-length key using PBKDF2.
     * Passwords are short and guessable, so PBKDF2 runs the hash many times
     * (100,000 here) to make each guess slow for an attacker.
     * The "salt" is random, public data that makes the same password give different keys.
     */
    public static function deriveKeyFromPassword(string $password, string $salt, int $bytes = 32): string
    {
        return hash_pbkdf2('sha256', $password, $salt, 100_000, $bytes, true);
    }

    /** Return the saved key called $name, or create + save a new one the first time. */
    public function getOrCreate(string $name, int $bytes = 32): string
    {
        if ($this->has($name)) {
            return $this->load($name);
        }
        $key = self::generateKey($bytes);
        $this->save($name, $key);
        return $key;
    }

    /** Save a raw binary key (stored as base64 text so the file is readable). */
    public function save(string $name, string $key): void
    {
        file_put_contents($this->path($name, 'key'), base64_encode($key));
    }

    public function load(string $name): string
    {
        $file = $this->path($name, 'key');
        if (!is_file($file)) {
            throw new RuntimeException("Key '$name' does not exist."); // `throw` works like in JS
        }
        return base64_decode((string) file_get_contents($file), true);
    }

    public function has(string $name): bool
    {
        return is_file($this->path($name, 'key'));
    }

    /** Delete a key. Used in lesson 05 to show "lost key = lost data". */
    public function delete(string $name): void
    {
        foreach (['key', 'pem'] as $ext) {
            $file = $this->path($name, $ext);
            if (is_file($file)) {
                unlink($file); // unlink = delete a file (Node: fs.unlinkSync)
            }
        }
    }

    /** Save / load text keys such as RSA "PEM" files (-----BEGIN PUBLIC KEY----- ...). */
    public function savePem(string $name, string $pem): void
    {
        file_put_contents($this->path($name, 'pem'), $pem);
    }

    public function loadPem(string $name): ?string
    {
        $file = $this->path($name, 'pem');
        return is_file($file) ? (string) file_get_contents($file) : null;
    }

    /** Build a safe file path: only letters, numbers, dash and underscore allowed in names. */
    private function path(string $name, string $ext): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $name);
        return $this->dir . '/' . $safe . '.' . $ext;
    }
}
