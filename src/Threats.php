<?php
/**
 * Threats.php — Threats to encryption.
 *
 *   1. BruteForce    — try every key until one works
 *   2. SideChannel   — learn secrets from TIMING, not the math
 *   3. Cryptanalysis — exploit weaknesses in how a cipher/hash is used
 *   4. Backdoor      — a hidden extra key for a third party
 *
 * Note: everything here attacks data WE create inside this demo. These are classroom
 * illustrations of why the defences in the other lessons exist.
 */

declare(strict_types=1);

/* ======================================================== 1. Brute force */

final class BruteForce
{
    /**
     * Encrypt a secret with a key made from a short numeric PIN.
     * A 4-digit PIN = only 10,000 possible keys -> the "key length" is tiny.
     */
    public static function encryptWithPin(string $secret, string $pin): string
    {
        return EncryptionEngine::encrypt($secret, self::pinToKey($pin));
    }

    /** Try every PIN from 000… to 999… until decryption succeeds. */
    public static function attack(string $package, int $digits): array
    {
        $raw = base64_decode($package);
        $iv  = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ct  = substr($raw, 28);

        $total = 10 ** $digits;  // ** is "to the power of", same as JS
        $start = hrtime(true);
        for ($i = 0; $i < $total; $i++) {
            $guess = str_pad((string) $i, $digits, '0', STR_PAD_LEFT); // 7 -> "0007" (JS: padStart)
            // AES-GCM tells us instantly if a key is wrong (the tag won't match).
            $plain = openssl_decrypt($ct, 'aes-256-gcm', self::pinToKey($guess), OPENSSL_RAW_DATA, $iv, $tag);
            if ($plain !== false) {
                $seconds = (hrtime(true) - $start) / 1e9;
                return [
                    'found'       => true,
                    'pin'         => $guess,
                    'plaintext'   => $plain,
                    'attempts'    => $i + 1,
                    'seconds'     => $seconds,
                    'keysPerSec'  => ($i + 1) / max($seconds, 1e-9),
                    'keyspace'    => $total,
                ];
            }
        }
        return ['found' => false, 'attempts' => $total, 'keyspace' => $total];
    }

    /**
     * The effectiveness of brute force depends on key length.
     * How long would trying EVERY key take at a given speed?
     */
    public static function estimate(float $keysPerSecond): array
    {
        $rows = [];
        foreach ([20 => '20-bit (≈ 6-digit PIN)', 40 => '40-bit (old "export grade")', 56 => '56-bit (DES)',
                  64 => '64-bit', 128 => '128-bit (AES-128)', 256 => '256-bit (AES-256)'] as $bits => $label) {
            $seconds = (2 ** $bits) / $keysPerSecond;
            $rows[]  = ['label' => $label, 'bits' => $bits, 'keys' => 2 ** $bits, 'human' => self::humanTime($seconds)];
        }
        return $rows;
    }

    public static function humanTime(float $seconds): string
    {
        $year = 365.25 * 24 * 3600;
        return match (true) {           // match(true) = a neat if/else-if chain
            $seconds < 1          => round($seconds * 1000, 2) . ' ms',
            $seconds < 120        => round($seconds, 1) . ' seconds',
            $seconds < 7200       => round($seconds / 60, 1) . ' minutes',
            $seconds < 172800     => round($seconds / 3600, 1) . ' hours',
            $seconds < $year      => round($seconds / 86400, 1) . ' days',
            $seconds < $year * 1e6 => number_format($seconds / $year, 0) . ' years',
            default               => sprintf('%.1e years', $seconds / $year) . ' (the universe is ~1.4e10 years old)',
        };
    }

    /** Deliberately weak: a fast hash of a short PIN. (Real systems use long random keys.) */
    private static function pinToKey(string $pin): string
    {
        return hash('sha256', $pin, true);
    }
}

/* ======================================================= 2. Side channel */

/**
 * A TIMING attack. The cipher is never broken — instead we watch how long a
 * password/token check takes. A naive check stops at the first wrong character,
 * so a guess with more correct leading characters takes LONGER. By timing
 * guesses we can recover the secret one character at a time.
 *
 * The real time difference is nanoseconds; we add a small artificial delay per
 * matching character (DELAY_US) so the effect is visible on a laptop.
 */
final class SideChannel
{
    public const ALPHABET = '0123456789abcdef';
    public const DELAY_US = 1500; // microseconds per correctly matched character (exaggerated)

    /** Vulnerable comparison — leaks how many leading characters are right. */
    public static function naiveCompare(string $guess, string $secret): bool
    {
        if (strlen($guess) !== strlen($secret)) {
            return false;
        }
        for ($i = 0; $i < strlen($secret); $i++) {
            if ($guess[$i] !== $secret[$i]) {
                return false;          // early exit = the leak
            }
            usleep(self::DELAY_US);    // simulated per-character work
        }
        return true;
    }

    /** Safe comparison — always takes the same time. */
    public static function safeCompare(string $guess, string $secret): bool
    {
        return hash_equals($secret, $guess);
    }

    /** Recover the secret using ONLY timing measurements of naiveCompare(). */
    public static function attack(string $secret): array
    {
        $length    = strlen($secret);
        $recovered = '';
        $log       = [];

        for ($pos = 0; $pos < $length; $pos++) {
            $timings = [];
            foreach (str_split(self::ALPHABET) as $candidate) {
                $guess = str_pad($recovered . $candidate, $length, 'x'); // fill the rest with junk
                [, $ms] = timed(fn () => self::naiveCompare($guess, $secret));
                $timings[$candidate] = $ms;
            }
            arsort($timings);                      // sort by time, slowest first
            $best       = (string) array_key_first($timings);
            $recovered .= $best;
            $log[]      = [
                'position' => $pos + 1,
                'chosen'   => $best,
                'slowest'  => round($timings[$best], 2),
                'median'   => round(self::median($timings), 2),
            ];
        }
        return ['recovered' => $recovered, 'success' => $recovered === $secret, 'log' => $log];
    }

    private static function median(array $values): float
    {
        $values = array_values($values);
        sort($values);
        return (float) $values[intdiv(count($values), 2)];
    }
}

/* ====================================================== 3. Cryptanalysis */

final class Cryptanalysis
{
    /**
     * ECB weakness: AES in ECB mode encrypts identical 16-byte blocks to identical
     * ciphertext blocks, revealing PATTERNS without knowing the key.
     * CBC/GCM mix in an IV so repeats disappear.
     */
    public static function ecbVsCbc(string $plaintext, string $key): array
    {
        $ecb = openssl_encrypt($plaintext, 'aes-256-ecb', $key, OPENSSL_RAW_DATA);
        $cbc = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, random_bytes(16));

        return [
            'plainBlocks' => str_split($plaintext, 16),
            'ecbBlocks'   => str_split(bin2hex($ecb), 32), // 16 bytes = 32 hex chars per block
            'cbcBlocks'   => str_split(bin2hex($cbc), 32),
        ];
    }

    /** Which blocks appear more than once? array_count_values ~ a frequency map. */
    public static function repeatedBlocks(array $blocks): array
    {
        return array_keys(array_filter(array_count_values($blocks), fn ($n) => $n > 1));
    }

    /**
     * Birthday attack: find two different inputs whose hashes match on the first
     * $bits bits. Expected effort is only about 2^(bits/2) tries — far less than
     * brute force (2^bits). That is why short hashes like MD5 (128-bit) are weak
     * on top of MD5's own mathematical flaws (real full MD5 collisions take seconds today).
     */
    public static function birthdayCollision(string $algorithm = 'md5', int $bits = 24, int $maxTries = 2_000_000): array
    {
        $hexChars = intdiv($bits, 4);
        $seen     = [];   // truncated-hash => input
        $start    = hrtime(true);

        for ($i = 1; $i <= $maxTries; $i++) {
            $input  = 'message-' . $i;
            $prefix = substr(hash($algorithm, $input), 0, $hexChars);
            if (isset($seen[$prefix])) {
                return [
                    'found'    => true,
                    'inputA'   => $seen[$prefix],
                    'inputB'   => $input,
                    'hashA'    => hash($algorithm, $seen[$prefix]),
                    'hashB'    => hash($algorithm, $input),
                    'prefix'   => $prefix,
                    'tries'    => $i,
                    'expected' => (int) round(sqrt(2 ** $bits) * 1.25),
                    'brute'    => 2 ** $bits,
                    'ms'       => (hrtime(true) - $start) / 1e6,
                ];
            }
            $seen[$prefix] = $input;
        }
        return ['found' => false, 'tries' => $maxTries];
    }
}

/* ========================================================= 4. Backdoor */

/**
 * A messenger that LOOKS secure (it really does use AES-256-GCM), but secretly
 * attaches a copy of every message key encrypted for a third party ("key escrow").
 * The user can't tell from the ciphertext — which is why open, publicly reviewed
 * algorithms and implementations matter.
 */
final class BackdooredMessenger
{
    public function __construct(private KeyManager $keys) {}

    /** The third party's RSA key pair (created once, stored by the KeyManager). */
    private function agencyKeys(): array
    {
        if ($this->keys->loadPem('agency-private') === null) {
            $pair = AsymmetricCiphers::rsaGenerateKeyPair(2048);
            $this->keys->savePem('agency-private', $pair['private']);
            $this->keys->savePem('agency-public', $pair['public']);
        }
        return ['private' => $this->keys->loadPem('agency-private'), 'public' => $this->keys->loadPem('agency-public')];
    }

    /** What the user thinks happens: encrypt with MY key. What also happens: a hidden key copy. */
    public function encrypt(string $message, string $userKey): array
    {
        return [
            'ciphertext' => EncryptionEngine::encrypt($message, $userKey),
            'metadata'   => AsymmetricCiphers::rsaEncrypt($userKey, $this->agencyKeys()['public']), // the backdoor
        ];
    }

    /** The third party decrypts WITHOUT ever being given the user's key. */
    public function agencyDecrypt(array $packet): string
    {
        $stolenKey = AsymmetricCiphers::rsaDecrypt($packet['metadata'], $this->agencyKeys()['private']);
        return EncryptionEngine::decrypt($packet['ciphertext'], $stolenKey);
    }
}
