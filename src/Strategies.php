<?php
/**
 * Strategies.php — Encryption implementation strategies.
 *
 * One small class per strategy. They all reuse the same building blocks:
 *   EncryptionEngine (AES-256-GCM), KeyManager, AsymmetricCiphers and Sodium.
 *
 *   1. ByoeDemo          — Bring Your Own Encryption / Key
 *   2. CloudStorage      — Cloud storage encryption
 *   3. ColumnEncryptedDb — Column-level database encryption
 *   4. E2eeDemo          — End-to-end encryption
 *   5. FieldLevel        — Field-level encryption on a web form
 *   6. HttpsDemo         — HTTPS / TLS certificates
 *   7. LinkLevel         — Link-level (hop-by-hop) encryption
 *   8. NetworkLevel      — Network-level encryption (IPsec-style)
 */

declare(strict_types=1);

/* ======================================================= 1. BYOE / BYOK */

/**
 * The CUSTOMER owns the key. The cloud app encrypts with it but never stores it,
 * so the provider holds only ciphertext it cannot read.
 */
final class ByoeDemo
{
    /** Customer side: turn the customer's own passphrase into a key and encrypt. */
    public static function customerEncrypts(string $customerPassphrase, string $data): array
    {
        $salt = random_bytes(16);
        $key  = KeyManager::deriveKeyFromPassword($customerPassphrase, $salt);
        // This array is EVERYTHING the cloud provider ever receives — no key.
        return [
            'salt'       => base64_encode($salt),
            'ciphertext' => EncryptionEngine::encrypt($data, $key),
        ];
    }

    /** Only someone who knows the customer's passphrase can get the data back. */
    public static function decryptWith(string $passphrase, array $storedRecord): string
    {
        $key = KeyManager::deriveKeyFromPassword($passphrase, base64_decode($storedRecord['salt']));
        return EncryptionEngine::decrypt($storedRecord['ciphertext'], $key);
    }
}

/* ============================================ 2. Cloud storage encryption */

/**
 * Files are encrypted BEFORE they are written to the "cloud" folder
 * (storage/.../cloud/). Open that folder in Finder/VS Code: the files are unreadable.
 * Here the PROVIDER manages the key (via KeyManager) — compare with BYOE above.
 */
final class CloudStorage
{
    private string $dir;

    public function __construct(private KeyManager $keys)
    {
        $this->dir = STORAGE_DIR . '/cloud';
        if (!is_dir($this->dir)) {
            mkdir($this->dir, 0700, true);
        }
    }

    public function upload(string $filename, string $content): string
    {
        $safe = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename) ?: 'file.txt';
        $key  = $this->keys->getOrCreate('cloud-storage');
        file_put_contents($this->dir . '/' . $safe . '.enc', EncryptionEngine::encrypt($content, $key));
        return $safe;
    }

    /** List the encrypted files. glob() ~ a filesystem wildcard search. */
    public function files(): array
    {
        $names = [];
        foreach (glob($this->dir . '/*.enc') ?: [] as $path) {
            $names[] = basename($path, '.enc');
        }
        return $names;
    }

    /** What an attacker who steals the disk would see. */
    public function rawContents(string $name): string
    {
        $path = $this->path($name);
        if (!is_file($path)) {
            throw new RuntimeException("File '$name' is not in the cloud storage.");
        }
        return (string) file_get_contents($path);
    }

    /** What the authorised app sees after decrypting with the key. */
    public function download(string $name): string
    {
        return EncryptionEngine::decrypt($this->rawContents($name), $this->keys->load('cloud-storage'));
    }

    public function delete(string $name): void
    {
        $path = $this->path($name);
        if (is_file($path)) {
            unlink($path);
        }
    }

    private function path(string $name): string
    {
        return $this->dir . '/' . basename($name) . '.enc'; // basename() blocks "../" tricks
    }
}

/* ================================================ 3. Column-level (DB) */

/**
 * A real SQLite database (storage/.../company.sqlite) with an `employees` table.
 * Only the `salary` column is encrypted, and EVERY cell in that column uses
 * the same column key.
 *
 * PDO = PHP's database layer (JS analogy: like `better-sqlite3` or `pg` clients).
 */
final class ColumnEncryptedDb
{
    private PDO $db;
    private const COLUMN_KEY = 'column-employees-salary';
    private const AAD        = 'employees.salary'; // ties each ciphertext to this column

    public function __construct(private KeyManager $keys)
    {
        if (!extension_loaded('pdo_sqlite')) {
            throw new RuntimeException('The pdo_sqlite PHP extension is missing (see README troubleshooting).');
        }
        $this->db = new PDO('sqlite:' . STORAGE_DIR . '/company.sqlite');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec('CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            salary_encrypted TEXT NOT NULL
        )');
    }

    public function insert(string $name, string $department, string $salary): void
    {
        $key = $this->keys->getOrCreate(self::COLUMN_KEY);
        // Prepared statement with ? placeholders = protection against SQL injection.
        $stmt = $this->db->prepare('INSERT INTO employees (name, department, salary_encrypted) VALUES (?, ?, ?)');
        $stmt->execute([$name, $department, EncryptionEngine::encrypt($salary, $key, self::AAD)]);
    }

    /** Rows exactly as stored on disk (what a DB admin or a SQL-injection attacker sees). */
    public function rawRows(): array
    {
        return $this->db->query('SELECT * FROM employees ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    }

    /** Rows as the authorised application sees them. array_map ~ JS .map(). */
    public function decryptedRows(): array
    {
        $key = $this->keys->getOrCreate(self::COLUMN_KEY);
        return array_map(function (array $row) use ($key): array {
            $row['salary'] = EncryptionEngine::decrypt($row['salary_encrypted'], $key, self::AAD);
            unset($row['salary_encrypted']); // remove a key from an array (JS: delete row.x)
            return $row;
        }, $this->rawRows());
    }

    public function clear(): void
    {
        $this->db->exec('DELETE FROM employees');
    }
}

/* ===================================================== 4. End-to-end (E2EE) */

/**
 * Alice and Bob each have a key pair (X25519 via Sodium, the same family of
 * crypto Signal and WhatsApp use). Alice encrypts with Bob's PUBLIC key + her
 * private key. The server only RELAYS the ciphertext — it has no key to read it.
 */
final class E2eeDemo
{
    public function __construct(private KeyManager $keys) {}

    /** Load a user's key pair, creating it on first use. */
    public function keyPair(string $user): string
    {
        $name = 'e2ee-' . $user;
        if (!$this->keys->has($name)) {
            // A key pair must be generated properly (public key is derived from the secret key),
            // so we don't use plain random bytes here.
            $this->keys->save($name, sodium_crypto_box_keypair());
        }
        return $this->keys->load($name);
    }

    public function publicKey(string $user): string
    {
        return sodium_crypto_box_publickey($this->keyPair($user));
    }

    /** Runs on the SENDER's device. */
    public function send(string $from, string $to, string $message): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        $pair  = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            sodium_crypto_box_secretkey($this->keyPair($from)),
            $this->publicKey($to)
        );
        return base64_encode($nonce . sodium_crypto_box($message, $nonce, $pair));
    }

    /** Runs on the RECIPIENT's device. Returns null if it can't be decrypted. */
    public function receive(string $to, string $from, string $packet): ?string
    {
        $raw   = base64_decode($packet, true) ?: '';
        $nonce = substr($raw, 0, SODIUM_CRYPTO_BOX_NONCEBYTES);
        $box   = substr($raw, SODIUM_CRYPTO_BOX_NONCEBYTES);
        $pair  = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            sodium_crypto_box_secretkey($this->keyPair($to)),
            $this->publicKey($from)
        );
        $plain = sodium_crypto_box_open($box, $nonce, $pair);
        return $plain === false ? null : $plain;
    }
}

/* ======================================================= 5. Field-level */

/**
 * Only the fields listed in SENSITIVE_FIELDS are encrypted — automatically —
 * before a form submission is stored. Everything else stays readable/searchable.
 */
final class FieldLevel
{
    public const SENSITIVE_FIELDS = ['card_number', 'ssn', 'bank_account', 'salary'];

    public function __construct(private KeyManager $keys) {}

    /** Encrypt the sensitive fields of a submitted form. */
    public function protect(array $form): array
    {
        $key = $this->keys->getOrCreate('field-level');
        foreach ($form as $field => $value) {                    // foreach ($obj as $k => $v) ~ Object.entries
            if (in_array($field, self::SENSITIVE_FIELDS, true) && $value !== '') {
                $form[$field] = 'enc:' . EncryptionEngine::encrypt($value, $key, $field);
            }
        }
        return $form;
    }

    /** Decrypt them again (only code with access to the key can do this). */
    public function reveal(array $record): array
    {
        $key = $this->keys->getOrCreate('field-level');
        foreach ($record as $field => $value) {
            if (str_starts_with($value, 'enc:')) {
                $record[$field] = EncryptionEngine::decrypt(substr($value, 4), $key, $field);
            }
        }
        return $record;
    }

    /** Show only the last 4 characters, e.g. for a card number on a receipt. */
    public static function mask(string $value): string
    {
        return str_repeat('•', max(0, strlen($value) - 4)) . substr($value, -4);
    }
}

/* ============================================================ 6. HTTPS */

/**
 * HTTPS = HTTP inside TLS. A web server needs a PUBLIC KEY CERTIFICATE.
 * We (a) create a self-signed certificate like a server would install, and
 * (b) simulate the core idea of the TLS handshake: use public-key crypto to
 *     agree on a symmetric session key, then use fast AES for the actual data.
 */
final class HttpsDemo
{
    /** Make a private key + a self-signed X.509 certificate for $domain. */
    public static function createSelfSignedCertificate(string $domain = 'localhost'): array
    {
        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new([
            'commonName'       => $domain,
            'organizationName' => 'Encryption Lab (demo)',
            'countryName'      => 'PH',
        ], $privateKey, ['digest_alg' => 'sha256']);
        $cert = openssl_csr_sign($csr, null, $privateKey, 365, ['digest_alg' => 'sha256']); // valid 365 days

        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($privateKey, $keyPem);
        $parsed = openssl_x509_parse($cert);

        return [
            'certificatePem' => $certPem,
            'privateKeyPem'  => $keyPem,
            'publicKeyPem'   => openssl_pkey_get_details($privateKey)['key'],
            'subject'        => $parsed['subject']['CN'] ?? '',
            'issuer'         => $parsed['issuer']['CN'] ?? '',
            'validFrom'      => date('Y-m-d H:i', $parsed['validFrom_time_t']),
            'validTo'        => date('Y-m-d H:i', $parsed['validTo_time_t']),
            'signatureAlgo'  => $parsed['signatureTypeSN'] ?? '',
            'fingerprint'    => openssl_x509_fingerprint($cert, 'sha256'),
        ];
    }

    /** Simplified handshake (TLS 1.2 "RSA key exchange" style) followed by encrypted traffic. */
    public static function simulateHandshake(string $httpRequest, array $server): array
    {
        $steps = [];
        $steps[] = ['Client → Server', 'Hello! I want to talk securely (ClientHello).'];
        $steps[] = ['Server → Client', 'Here is my certificate for "' . $server['subject'] . '" (contains my PUBLIC key).'];

        $sessionKey = KeyManager::generateKey(); // random AES key, fresh for this connection
        $wrappedKey = AsymmetricCiphers::rsaEncrypt($sessionKey, $server['publicKeyPem']);
        $steps[] = ['Client → Server', 'Random session key, encrypted with the server\'s PUBLIC key: ' . shorten($wrappedKey, 60)];

        $serverSessionKey = AsymmetricCiphers::rsaDecrypt($wrappedKey, $server['privateKeyPem']);
        $steps[] = ['Server', 'Decrypts it with its PRIVATE key. Both sides now share the same AES key: '
            . (hash_equals($sessionKey, $serverSessionKey) ? 'yes' : 'no')];

        $encryptedRequest = EncryptionEngine::encrypt($httpRequest, $sessionKey);
        $steps[] = ['Client → Server', 'HTTP request encrypted with AES (this is all a Wi-Fi eavesdropper sees): ' . shorten($encryptedRequest, 60)];
        $steps[] = ['Server', 'Decrypted request: ' . EncryptionEngine::decrypt($encryptedRequest, $serverSessionKey)];

        return $steps;
    }
}

/* ====================================================== 7. Link-level */

/**
 * The message travels Sender → Router A → Router B → Recipient.
 * Each LINK has its own key and even its own algorithm. Every node
 * decrypts what it received and re-encrypts it for the next link — so the
 * message is briefly in PLAINTEXT inside each router (unlike E2EE).
 */
final class LinkLevel
{
    public const ROUTE = ['Sender', 'Router A', 'Router B', 'Recipient'];
    public const LINK_ALGORITHMS = ['AES-256', 'Twofish', '3DES']; // one per link

    public static function send(string $message): array
    {
        // Each neighbouring pair shares its own key.
        $linkKeys = [];
        foreach (self::LINK_ALGORITHMS as $i => $algo) {
            $linkKeys[$i] = SymmetricCiphers::generateKey($algo);
        }

        $log    = [];
        $packet = SymmetricCiphers::encrypt(self::LINK_ALGORITHMS[0], $message, $linkKeys[0]);
        $log[]  = ['node' => 'Sender', 'action' => 'Encrypts with link-1 key (' . self::LINK_ALGORITHMS[0] . ')', 'data' => $packet];

        for ($i = 1; $i < count(self::ROUTE); $i++) {
            $node      = self::ROUTE[$i];
            $plaintext = SymmetricCiphers::decrypt(self::LINK_ALGORITHMS[$i - 1], $packet, $linkKeys[$i - 1]);
            $isRelay   = $i < count(self::ROUTE) - 1;
            $log[]     = ['node' => $node, 'action' => "Decrypts with link-$i key (" . self::LINK_ALGORITHMS[$i - 1] . ')'
                . ($isRelay ? ' → plaintext visible inside this router!' : ' → message delivered'), 'data' => $plaintext, 'exposed' => $isRelay];

            if ($i < count(self::ROUTE) - 1) {
                $packet = SymmetricCiphers::encrypt(self::LINK_ALGORITHMS[$i], $plaintext, $linkKeys[$i]);
                $log[]  = ['node' => $node, 'action' => 'Re-encrypts with link-' . ($i + 1) . ' key (' . self::LINK_ALGORITHMS[$i] . ') and forwards', 'data' => $packet];
            }
        }
        return $log;
    }
}

/* ===================================================== 8. Network-level */

/**
 * IPsec (ESP, tunnel mode) idea: the whole inner packet — including who it is
 * really for and the data — is encrypted. Only a new outer header between the
 * two VPN gateways stays readable so routers can deliver it. The outer header is
 * authenticated (via AES-GCM's AAD), so it can't be altered without detection.
 */
final class NetworkLevel
{
    public static function encapsulate(array $innerPacket, string $tunnelKey, string $gatewayA, string $gatewayB, int $spi): array
    {
        $outerHeader = ['src' => $gatewayA, 'dst' => $gatewayB, 'protocol' => 'ESP (50)', 'spi' => $spi];
        $aad         = json_encode($outerHeader);       // JSON.stringify
        return [
            'header'  => $outerHeader,
            'payload' => EncryptionEngine::encrypt(json_encode($innerPacket), $tunnelKey, $aad),
        ];
    }

    public static function decapsulate(array $espPacket, string $tunnelKey): array
    {
        $json = EncryptionEngine::decrypt($espPacket['payload'], $tunnelKey, json_encode($espPacket['header']));
        return json_decode($json, true); // JSON.parse (true = give arrays, not objects)
    }
}
