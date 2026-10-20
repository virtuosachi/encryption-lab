<?php
/**
 * Hashing.php — Cryptographic hashing algorithms.
 *
 * A HASH turns any input into a FIXED-LENGTH "fingerprint".
 * It is ONE-WAY: there is no key and no "unhash" function.
 *
 * The four properties — each has a function below that proves it:
 *   1. Computationally efficient -> fast to compute            (see timing in hashAll)
 *   2. Deterministic             -> same input = same output    (isDeterministic)
 *   3. Preimage-resistant        -> output reveals nothing about the input
 *   4. Collision-resistant       -> two inputs almost never share a hash
 *   + Bonus: the "avalanche effect" — change 1 character, ~50% of output bits flip (avalanche)
 *
 * Note on hex length: each hex character stores 4 bits, so
 *   SHA-256 = 64 hex chars × 4 = 256 bits,   MD5 = 32 hex chars × 4 = 128 bits.
 */

declare(strict_types=1);

final class Hashing
{
    /** Common hash algorithms (name => description). */
    public const ALGORITHMS = [
        'md5'      => ['MD5',      'Broken — collisions are easy to create. OK only for non-security checksums.'],
        'sha1'     => ['SHA-1',    'Broken for collisions since 2017. Succeeded by SHA-2.'],
        'sha256'   => ['SHA-256',  'SHA-2 family. The current workhorse (TLS certificates, Bitcoin, Git\'s new format).'],
        'sha512'   => ['SHA-512',  'SHA-2 family, longer output.'],
        'sha3-256' => ['SHA-3-256','Newest NIST standard (2015). Completely different internal design from SHA-2.'],
        'blake2b'  => ['BLAKE2b',  'Fast modern hash (from the BLAKE family). Provided by PHP\'s Sodium extension.'],
    ];

    /** Hash with one algorithm and return hex. */
    public static function hash(string $algorithm, string $input): string
    {
        if ($algorithm === 'blake2b') {
            // PHP's hash() doesn't include BLAKE, but Sodium does (32-byte output = 256 bits).
            return bin2hex(sodium_crypto_generichash($input));
        }
        return hash($algorithm, $input); // JS: crypto.createHash('sha256').update(input).digest('hex')
    }

    /** Hash the input with every algorithm, with length, bits and time taken. */
    public static function hashAll(string $input): array
    {
        $results = [];
        foreach (self::ALGORITHMS as $algo => [$label, $note]) {
            [$digest, $ms] = timed(fn () => self::hash($algo, $input));
            $results[] = [
                'algo'   => $algo,
                'label'  => $label,
                'note'   => $note,
                'digest' => $digest,
                'chars'  => strlen($digest),
                'bits'   => strlen($digest) * 4,
                'ms'     => $ms,
            ];
        }
        return $results;
    }

    /** Property 2: hashing the same input many times always gives the same digest. */
    public static function isDeterministic(string $input, string $algorithm = 'sha256', int $times = 5): bool
    {
        $first = self::hash($algorithm, $input);
        for ($i = 1; $i < $times; $i++) {
            if (self::hash($algorithm, $input) !== $first) {
                return false;
            }
        }
        return true;
    }

    /**
     * Avalanche effect: how many output BITS change between two inputs?
     * For a good hash, a 1-character change flips about half of them.
     */
    public static function avalanche(string $a, string $b, string $algorithm = 'sha256'): array
    {
        $hashA = self::hash($algorithm, $a);
        $hashB = self::hash($algorithm, $b);

        $binA = hex2bin($hashA);
        $binB = hex2bin($hashB);
        $changedBits = 0;
        for ($i = 0; $i < strlen($binA); $i++) {
            // XOR (^) marks the bits that differ; count the 1s in the result.
            $changedBits += substr_count(decbin(ord($binA[$i]) ^ ord($binB[$i])), '1');
        }
        $totalBits = strlen($binA) * 8;

        return [
            'hashA'       => $hashA,
            'hashB'       => $hashB,
            'changedBits' => $changedBits,
            'totalBits'   => $totalBits,
            'percent'     => round($changedBits / $totalBits * 100, 1),
        ];
    }

    /**
     * Integrity check: compare a file/message against a known-good hash.
     * hash_equals() compares in constant time (see the side-channel demo in lesson 07).
     */
    public static function verifyIntegrity(string $message, string $expectedHex, string $algorithm = 'sha256'): bool
    {
        return hash_equals(strtolower(trim($expectedHex)), self::hash($algorithm, $message));
    }

    /**
     * HMAC = a hash mixed with a SECRET key. Only someone who knows the key can
     * produce a valid HMAC, so it proves the message came from a key holder (authentication).
     */
    public static function hmac(string $message, string $key): string
    {
        return hash_hmac('sha256', $message, $key);
    }

    /**
     * Passwords: never store them encrypted or with a plain fast hash.
     * password_hash() uses bcrypt with a random salt and is deliberately slow.
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    public static function checkPassword(string $password, string $storedHash): bool
    {
        return password_verify($password, $storedHash);
    }
}
