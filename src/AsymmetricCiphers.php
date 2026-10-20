<?php
/**
 * AsymmetricCiphers.php — Asymmetric (public-key) encryption algorithms.
 *
 * ASYMMETRIC (public-key) = TWO linked keys:
 *   - PUBLIC key  -> share it with everyone
 *   - PRIVATE key -> never leaves its owner
 *
 *   Encrypt with PUBLIC  -> only the PRIVATE key can decrypt   (confidentiality)
 *   Sign with PRIVATE    -> anyone with the PUBLIC key verifies (authenticity / nonrepudiation)
 *   That second line is the "or vice versa" of public-key crypto.
 *
 * Algorithms covered:
 *   RSA — security comes from how hard it is to factor huge numbers.
 *   ECC — elliptic curves: same security with MUCH shorter keys.
 *   Diffie-Hellman — two people agree on a shared secret over a public channel.
 *   DSS — the Digital Signature Standard; ECDSA is its modern form.
 *   ElGamal — encryption built on the same math as Diffie-Hellman.
 *
 * RSA, ECC and DSS use PHP's built-in OpenSSL extension. The Diffie-Hellman and
 * ElGamal "toy" versions use tiny numbers so you can follow the math by hand;
 * X25519 (via the built-in Sodium extension) shows the real-world version of Diffie-Hellman.
 */

declare(strict_types=1);

final class AsymmetricCiphers
{
    /* =========================================================== RSA ===== */

    /**
     * Create an RSA key pair. Returns ['private' => PEM, 'public' => PEM].
     * PEM = the text format that starts with "-----BEGIN ... KEY-----".
     * 2048 bits is the minimum today; 3072+ is recommended for long-term use.
     */
    public static function rsaGenerateKeyPair(int $bits = 2048): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($key === false) {
            throw new RuntimeException('Could not generate RSA keys: ' . openssl_error_string());
        }
        openssl_pkey_export($key, $privatePem);          // $privatePem is filled in "by reference"
        $publicPem = openssl_pkey_get_details($key)['key'];

        return ['private' => $privatePem, 'public' => $publicPem];
    }

    /**
     * Encrypt with the recipient's PUBLIC key.
     * OAEP padding adds randomness so the same message encrypts differently each time.
     * Limit: RSA can only encrypt a SHORT message (~214 bytes for a 2048-bit key).
     * Real systems therefore use RSA to send an AES key, then AES for the data ("hybrid").
     */
    public static function rsaEncrypt(string $plaintext, string $publicPem): string
    {
        if (!openssl_public_encrypt($plaintext, $ciphertext, $publicPem, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('RSA encryption failed (message too long? RSA-2048 + OAEP allows max 214 bytes).');
        }
        return base64_encode($ciphertext);
    }

    /** Decrypt with your own PRIVATE key. */
    public static function rsaDecrypt(string $ciphertextB64, string $privatePem): string
    {
        $ciphertext = base64_decode($ciphertextB64, true);
        if ($ciphertext === false || !openssl_private_decrypt($ciphertext, $plaintext, $privatePem, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new RuntimeException('RSA decryption failed — wrong private key or corrupted ciphertext.');
        }
        return $plaintext;
    }

    /** "Vice versa": SIGN with the PRIVATE key (works for RSA and EC keys). */
    public static function sign(string $message, string $privatePem): string
    {
        if (!openssl_sign($message, $signature, $privatePem, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Signing failed: ' . openssl_error_string());
        }
        return base64_encode($signature);
    }

    /** VERIFY a signature with the matching PUBLIC key. true = genuine and unchanged. */
    public static function verify(string $message, string $signatureB64, string $publicPem): bool
    {
        $signature = base64_decode($signatureB64, true);
        if ($signature === false) {
            return false;
        }
        return openssl_verify($message, $signature, $publicPem, OPENSSL_ALGO_SHA256) === 1;
    }

    /* =========================================================== ECC ===== */

    /**
     * Create an Elliptic-Curve key pair on curve P-256 ("prime256v1").
     * A 256-bit EC key ≈ the security of a 3072-bit RSA key.
     */
    public static function ecGenerateKeyPair(string $curve = 'prime256v1'): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => $curve,
        ]);
        if ($key === false) {
            throw new RuntimeException('Could not generate EC keys: ' . openssl_error_string());
        }
        openssl_pkey_export($key, $privatePem);
        $publicPem = openssl_pkey_get_details($key)['key'];

        return ['private' => $privatePem, 'public' => $publicPem];
    }

    /**
     * ECDH: combine MY private key with YOUR public key -> a shared secret.
     * You doing the same with your private key + my public key gives the SAME secret.
     * We hash it with SHA-256 to get a clean 32-byte AES key.
     */
    public static function ecdhSharedKey(string $myPrivatePem, string $theirPublicPem): string
    {
        $secret = openssl_pkey_derive($theirPublicPem, $myPrivatePem);
        if ($secret === false) {
            throw new RuntimeException('ECDH failed: ' . openssl_error_string());
        }
        return hash('sha256', $secret, true);
    }

    /* ================================================ Diffie-Hellman ===== */

    /**
     * Fast "modular exponentiation": (base ^ exp) % mod without huge numbers.
     * Used by the toy Diffie-Hellman and ElGamal below.
     */
    public static function modPow(int $base, int $exp, int $mod): int
    {
        $result = 1;
        $base %= $mod;
        while ($exp > 0) {
            if ($exp & 1) {                       // if the lowest bit is 1
                $result = ($result * $base) % $mod;
            }
            $base = ($base * $base) % $mod;
            $exp >>= 1;                           // shift right = divide by 2
        }
        return $result;
    }

    /**
     * TOY Diffie-Hellman with small public numbers p (a prime) and g (a generator).
     * Returns every step so the page can show the math.
     * Real DH uses 2048+ bit primes, or elliptic curves (see x25519Demo).
     */
    public static function toyDiffieHellman(int $p = 23, int $g = 5): array
    {
        $alicePrivate = random_int(2, $p - 2);  // secret numbers (random_int = secure Math.random)
        $bobPrivate   = random_int(2, $p - 2);

        $alicePublic  = self::modPow($g, $alicePrivate, $p); // A = g^a mod p  (sent in the open)
        $bobPublic    = self::modPow($g, $bobPrivate, $p);   // B = g^b mod p  (sent in the open)

        $aliceSecret  = self::modPow($bobPublic, $alicePrivate, $p); // B^a mod p
        $bobSecret    = self::modPow($alicePublic, $bobPrivate, $p); // A^b mod p

        // compact() builds ['p' => $p, 'g' => $g, ...] from variable names
        return compact('p', 'g', 'alicePrivate', 'bobPrivate', 'alicePublic', 'bobPublic', 'aliceSecret', 'bobSecret');
    }

    /** Real-world Diffie-Hellman on Curve25519 (what Signal/WhatsApp and TLS 1.3 use). */
    public static function x25519Demo(): array
    {
        $alice = sodium_crypto_box_keypair();
        $bob   = sodium_crypto_box_keypair();

        $alicePublic = sodium_crypto_box_publickey($alice);
        $bobPublic   = sodium_crypto_box_publickey($bob);

        $aliceShared = sodium_crypto_scalarmult(sodium_crypto_box_secretkey($alice), $bobPublic);
        $bobShared   = sodium_crypto_scalarmult(sodium_crypto_box_secretkey($bob), $alicePublic);

        return [
            'alicePublic' => hex($alicePublic),
            'bobPublic'   => hex($bobPublic),
            'aliceShared' => hex($aliceShared),
            'bobShared'   => hex($bobShared),
        ];
    }

    /* ======================================================= ElGamal ===== */

    /**
     * TOY ElGamal key pair. Public key = (p, g, y = g^x mod p); private key = x.
     * p = 467 is prime and bigger than any single-byte character code (0–255).
     */
    public static function toyElGamalKeys(int $p = 467, int $g = 2): array
    {
        $x = random_int(2, $p - 2);
        return ['p' => $p, 'g' => $g, 'y' => self::modPow($g, $x, $p), 'x' => $x];
    }

    /**
     * Encrypt each byte m as the pair (c1, c2):  c1 = g^k,  c2 = m · y^k  (mod p),
     * with a fresh random k for every byte.
     */
    public static function toyElGamalEncrypt(string $message, array $pub): array
    {
        ['p' => $p, 'g' => $g, 'y' => $y] = $pub; // destructuring, like JS: const { p, g, y } = pub
        $pairs = [];
        foreach (str_split($message) as $char) {   // str_split ~ [...message]
            $k       = random_int(2, $p - 2);
            $pairs[] = [self::modPow($g, $k, $p), (ord($char) * self::modPow($y, $k, $p)) % $p]; // $arr[] = push
        }
        return $pairs;
    }

    /** Decrypt: m = c2 · (c1^x)^-1 mod p. The inverse uses Fermat's little theorem: s^(p-2). */
    public static function toyElGamalDecrypt(array $pairs, int $x, int $p): string
    {
        $out = '';
        foreach ($pairs as [$c1, $c2]) {
            $s       = self::modPow($c1, $x, $p);
            $sInv    = self::modPow($s, $p - 2, $p);
            $out    .= chr(($c2 * $sInv) % $p);   // .= is string append (JS: +=)
        }
        return $out;
    }

    /* ================================================= Speed */

    /**
     * "Symmetric is typically faster than asymmetric." Let's measure it.
     * Encrypt + decrypt the same short message N times with AES and with RSA.
     */
    public static function benchmark(int $rounds = 200): array
    {
        $message = str_repeat('A', 100);

        // --- AES-256-GCM
        $aesKey = KeyManager::generateKey();
        [, $aesKeygenMs] = timed(fn () => KeyManager::generateKey());
        [, $aesMs] = timed(function () use ($rounds, $message, $aesKey) { // `use` = capture outer vars into the closure
            for ($i = 0; $i < $rounds; $i++) {
                EncryptionEngine::decrypt(EncryptionEngine::encrypt($message, $aesKey), $aesKey);
            }
        });

        // --- RSA-2048
        [$rsa, $rsaKeygenMs] = timed(fn () => self::rsaGenerateKeyPair(2048));
        [, $rsaMs] = timed(function () use ($rounds, $message, $rsa) {
            for ($i = 0; $i < $rounds; $i++) {
                self::rsaDecrypt(self::rsaEncrypt($message, $rsa['public']), $rsa['private']);
            }
        });

        return [
            'rounds'      => $rounds,
            'aesMs'       => $aesMs,
            'rsaMs'       => $rsaMs,
            'aesKeygenMs' => $aesKeygenMs,
            'rsaKeygenMs' => $rsaKeygenMs,
            'times'       => $aesMs > 0 ? $rsaMs / $aesMs : 0,
        ];
    }
}
