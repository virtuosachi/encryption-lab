<?php
/**
 * SymmetricCiphers.php — Symmetric encryption algorithms.
 *
 * SYMMETRIC = ONE shared key does both jobs:
 *      plaintext --[key]--> ciphertext --[same key]--> plaintext
 *
 * Algorithms covered:
 *   AES — the modern standard. 128-bit blocks, 128/192/256-bit keys.
 *   DES — outdated. Only a 56-bit key -> brute-forceable in hours today.
 *   3DES — DES applied 3 times to patch the short key. Deprecated, slow.
 *   Blowfish — older 64-bit block cipher (predecessor of Twofish).
 *   Twofish — 128-bit block, 128/192/256-bit key, key-dependent S-boxes.
 *
 * To compare them fairly, all five use the same "mode": CBC (Cipher Block Chaining)
 * with a random IV. For real apps prefer EncryptionEngine (AES-GCM), which also
 * detects tampering.
 *
 * Where does each implementation come from?
 *   - AES and 3DES: PHP's built-in OpenSSL extension.
 *   - DES, Blowfish, Twofish: the bundled phpseclib library. Modern OpenSSL 3
 *     disables DES and Blowfish because they are insecure, and Twofish was never
 *     included in PHP, so we use a pure-PHP implementation instead.
 */

declare(strict_types=1);

use phpseclib3\Crypt\Blowfish;
use phpseclib3\Crypt\DES;
use phpseclib3\Crypt\Twofish;
// `use` = import (TS: import { Twofish } from 'phpseclib3/Crypt')

final class SymmetricCiphers
{
    /**
     * Info about each algorithm. This is an "associative array" — PHP's version
     * of a JS object / TS Record<string, {...}>.
     */
    public const ALGORITHMS = [
        'AES-256' => [
            'keyBytes' => 32, 'blockBytes' => 16, 'year' => 2001,
            'status'   => 'Recommended',
            'note'     => 'Chosen by NIST to replace DES. Used everywhere (HTTPS, Wi-Fi, disk encryption).',
        ],
        'DES' => [
            'keyBytes' => 8, 'blockBytes' => 8, 'year' => 1977,
            'status'   => 'Broken',
            'note'     => '64-bit key but only 56 bits are used. Can be brute-forced. Superseded by AES.',
        ],
        '3DES' => [
            'keyBytes' => 24, 'blockBytes' => 8, 'year' => 1998,
            'status'   => 'Deprecated',
            'note'     => 'Runs DES three times (encrypt-decrypt-encrypt). Safer than DES but slow; retired by NIST in 2023.',
        ],
        'Blowfish' => [
            'keyBytes' => 16, 'blockBytes' => 8, 'year' => 1993,
            'status'   => 'Legacy',
            'note'     => 'Fast and free, but its 64-bit block is too small for large amounts of data.',
        ],
        'Twofish' => [
            'keyBytes' => 32, 'blockBytes' => 16, 'year' => 1998,
            'status'   => 'Secure (rarely used)',
            'note'     => 'AES finalist. 128-bit block, key-dependent S-boxes. Open source and free.',
        ],
    ];

    /** Make a random key of the right size for the chosen algorithm. */
    public static function generateKey(string $algorithm): string
    {
        return random_bytes(self::info($algorithm)['keyBytes']);
    }

    /**
     * Encrypt with the chosen algorithm (CBC mode).
     * Returns base64( IV + ciphertext ).
     */
    public static function encrypt(string $algorithm, string $plaintext, string $key): string
    {
        $info = self::info($algorithm);
        self::checkKey($algorithm, $key);
        $iv = random_bytes($info['blockBytes']); // IV is always one block long

        // `match` is like a JS switch that RETURNS a value and uses strict ===.
        $ciphertext = match ($algorithm) {
            'AES-256'  => openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv),
            '3DES'     => openssl_encrypt($plaintext, 'des-ede3-cbc', $key, OPENSSL_RAW_DATA, $iv),
            'DES', 'Blowfish', 'Twofish' => self::phpseclibCipher($algorithm, $key, $iv)->encrypt($plaintext),
        };

        if ($ciphertext === false) {
            throw new RuntimeException("$algorithm encryption failed: " . openssl_error_string());
        }
        return base64_encode($iv . $ciphertext);
    }

    /** Reverse of encrypt(). Needs the SAME key — that's what makes it symmetric. */
    public static function decrypt(string $algorithm, string $package, string $key): string
    {
        $info = self::info($algorithm);
        self::checkKey($algorithm, $key);

        $raw = base64_decode($package, true);
        if ($raw === false || strlen($raw) <= $info['blockBytes']) {
            throw new RuntimeException('Not a valid ciphertext for ' . $algorithm . '.');
        }
        $iv         = substr($raw, 0, $info['blockBytes']);
        $ciphertext = substr($raw, $info['blockBytes']);

        try {
            $plaintext = match ($algorithm) {
                'AES-256'  => openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv),
                '3DES'     => openssl_decrypt($ciphertext, 'des-ede3-cbc', $key, OPENSSL_RAW_DATA, $iv),
                'DES', 'Blowfish', 'Twofish' => self::phpseclibCipher($algorithm, $key, $iv)->decrypt($ciphertext),
            };
        } catch (Throwable) { // phpseclib throws on bad padding (usually = wrong key)
            $plaintext = false;
        }

        if ($plaintext === false) {
            // CBC has no tamper check: a wrong key usually breaks the padding, which we detect here.
            throw new RuntimeException("$algorithm decryption failed — most likely the wrong key.");
        }
        return $plaintext;
    }

    /** Build a phpseclib cipher object in CBC mode with our key and IV. */
    private static function phpseclibCipher(string $algorithm, string $key, string $iv): DES|Blowfish|Twofish
    {
        $cipher = match ($algorithm) {
            'DES'      => new DES('cbc'),
            'Blowfish' => new Blowfish('cbc'),
            'Twofish'  => new Twofish('cbc'),
        };
        $cipher->setKey($key);
        $cipher->setIV($iv);
        return $cipher; // PKCS#7 padding is on by default, same as OpenSSL
    }

    public static function info(string $algorithm): array
    {
        if (!isset(self::ALGORITHMS[$algorithm])) {
            throw new InvalidArgumentException("Unknown algorithm: $algorithm");
        }
        return self::ALGORITHMS[$algorithm];
    }

    private static function checkKey(string $algorithm, string $key): void
    {
        $need = self::info($algorithm)['keyBytes'];
        if (strlen($key) !== $need) {
            throw new InvalidArgumentException("$algorithm needs a $need-byte key, got " . strlen($key) . ' bytes.');
        }
    }
}
