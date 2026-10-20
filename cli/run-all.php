<?php
/**
 * run-all.php — run EVERY demo from the lesson in the terminal, no browser needed.
 *
 *   php cli/run-all.php
 *
 * JS analogy: like `node scripts/run-all.js`. Handy for a quick check that your
 * PHP install has everything the web pages need.
 */

declare(strict_types=1);

require __DIR__ . '/../src/bootstrap.php';

// Small helpers for pretty terminal output.
function title(string $text): void { echo "\n\033[1;34m=== $text ===\033[0m\n"; }
function line(string $label, string $value): void { printf("  %-28s %s\n", $label . ':', $value); }
function ok(bool $pass): string { return $pass ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m"; }

$message = 'Hello, world!';
$allPassed = true;
$check = function (bool $pass) use (&$allPassed): string { // &$allPassed = capture by reference
    $allPassed = $allPassed && $pass;
    return ok($pass);
};

/* ---------- 01 Basics */
title('01 Basics — Data + Encryption Engine + Key Manager');
$key    = $keyManager->getOrCreate('cli-demo');
$cipher = EncryptionEngine::encrypt($message, $key);
line('Plaintext', $message);
line('Ciphertext (AES-256-GCM)', $cipher);
line('Decrypted', EncryptionEngine::decrypt($cipher, $key) . '  ' . $check(EncryptionEngine::decrypt($cipher, $key) === $message));

/* ---------- 02 Symmetric */
title('02 Symmetric — one shared key');
foreach (array_keys(SymmetricCiphers::ALGORITHMS) as $algo) {
    $k  = SymmetricCiphers::generateKey($algo);
    $ct = SymmetricCiphers::encrypt($algo, $message, $k);
    line($algo, shorten($ct, 44) . '  ' . $check(SymmetricCiphers::decrypt($algo, $ct, $k) === $message));
}

/* ---------- 03 Asymmetric */
title('03 Asymmetric — public/private key pairs');
$rsa = AsymmetricCiphers::rsaGenerateKeyPair(2048);
$ct  = AsymmetricCiphers::rsaEncrypt($message, $rsa['public']);
line('RSA encrypt/decrypt', $check(AsymmetricCiphers::rsaDecrypt($ct, $rsa['private']) === $message));
$sig = AsymmetricCiphers::sign($message, $rsa['private']);
line('RSA sign/verify', $check(AsymmetricCiphers::verify($message, $sig, $rsa['public'])));
line('RSA tampered verify fails', $check(!AsymmetricCiphers::verify($message . '!', $sig, $rsa['public'])));

$alice = AsymmetricCiphers::ecGenerateKeyPair();
$bob   = AsymmetricCiphers::ecGenerateKeyPair();
line('ECDSA (DSS) sign/verify', $check(AsymmetricCiphers::verify($message, AsymmetricCiphers::sign($message, $alice['private']), $alice['public'])));
line('ECDH shared key matches', $check(AsymmetricCiphers::ecdhSharedKey($alice['private'], $bob['public']) === AsymmetricCiphers::ecdhSharedKey($bob['private'], $alice['public'])));

$dh = AsymmetricCiphers::toyDiffieHellman();
line('Toy Diffie-Hellman', "p={$dh['p']} g={$dh['g']} secret={$dh['aliceSecret']}/{$dh['bobSecret']} " . $check($dh['aliceSecret'] === $dh['bobSecret']));
$x = AsymmetricCiphers::x25519Demo();
line('X25519 Diffie-Hellman', $check($x['aliceShared'] === $x['bobShared']));

$eg = AsymmetricCiphers::toyElGamalKeys();
line('Toy ElGamal', $check(AsymmetricCiphers::toyElGamalDecrypt(AsymmetricCiphers::toyElGamalEncrypt($message, $eg), $eg['x'], $eg['p']) === $message));

$bench = AsymmetricCiphers::benchmark(100);
line('Speed (100 enc+dec)', sprintf('AES %.1f ms vs RSA %.1f ms → RSA ~%.0fx slower', $bench['aesMs'], $bench['rsaMs'], $bench['times']));

/* ---------- 04 Hashing */
title('04 Hashing — "Hello, world!"');
foreach (Hashing::hashAll($message) as $r) {
    line($r['label'] . " ({$r['bits']} bits)", $r['digest']);
}
$av = Hashing::avalanche('Hello, world!', 'Hello, world?');
line('Avalanche (! → ?)', "{$av['changedBits']}/{$av['totalBits']} bits changed ({$av['percent']}%)");
line('Deterministic', $check(Hashing::isDeterministic($message)));
$pw = Hashing::hashPassword('s3cret');
line('Password hash/verify', $check(Hashing::checkPassword('s3cret', $pw) && !Hashing::checkPassword('wrong', $pw)));

/* ---------- 05 Security goals */
title('05 Security goals');
$hmacKey = random_bytes(32);
line('Integrity (SHA-256)', $check(Hashing::verifyIntegrity($message, hash('sha256', $message)) && !Hashing::verifyIntegrity($message . 'x', hash('sha256', $message))));
line('Authentication (HMAC)', $check(hash_equals(Hashing::hmac($message, $hmacKey), Hashing::hmac($message, $hmacKey))));
try {
    $tampered = base64_encode(substr_replace(base64_decode($cipher), 'X', -1));
    EncryptionEngine::decrypt($tampered, $key);
    line('GCM detects tampering', $check(false));
} catch (RuntimeException) {
    line('GCM detects tampering', $check(true));
}

/* ---------- 06 Strategies */
title('06 Implementation strategies');
$rec = ByoeDemo::customerEncrypts('my own passphrase', 'customer secret');
line('BYOE', $check(ByoeDemo::decryptWith('my own passphrase', $rec) === 'customer secret'));

$cloud = new CloudStorage($keyManager);
$name  = $cloud->upload('cli-test.txt', 'cloud content');
line('Cloud storage', $check($cloud->download($name) === 'cloud content'));
$cloud->delete($name);

$db = new ColumnEncryptedDb($keyManager);
$db->insert('CLI Tester', 'IT', '12345');
$rows = $db->decryptedRows();
line('Column-level (SQLite)', $check(end($rows)['salary'] === '12345'));

$e2ee = new E2eeDemo($keyManager);
$pkt  = $e2ee->send('alice', 'bob', 'hi bob');
line('E2EE (Alice → Bob)', $check($e2ee->receive('bob', 'alice', $pkt) === 'hi bob'));
line('E2EE (server/Eve can\'t read)', $check($e2ee->receive('eve', 'alice', $pkt) === null));

$fl  = new FieldLevel($keyManager);
$rec = $fl->protect(['name' => 'Ana', 'card_number' => '4111111111111111']);
line('Field-level', $check(str_starts_with($rec['card_number'], 'enc:') && $rec['name'] === 'Ana' && $fl->reveal($rec)['card_number'] === '4111111111111111'));

$server = HttpsDemo::createSelfSignedCertificate('localhost');
line('HTTPS certificate', "CN={$server['subject']}  valid until {$server['validTo']}");
$steps = HttpsDemo::simulateHandshake('GET /account HTTP/1.1', $server);
line('TLS-style handshake', $check(str_contains(end($steps)[1], 'GET /account')));

$log = LinkLevel::send('link message');
line('Link-level (3 links)', $check(end($log)['data'] === 'link message'));

$tk  = KeyManager::generateKey();
$esp = NetworkLevel::encapsulate(['src' => '10.0.1.5', 'dst' => '10.0.2.9', 'data' => 'payroll'], $tk, '203.0.113.1', '198.51.100.7', 4242);
line('Network-level (IPsec-style)', $check(NetworkLevel::decapsulate($esp, $tk)['data'] === 'payroll'));

/* ---------- 07 Threats */
title('07 Threats');
$bf = BruteForce::attack(BruteForce::encryptWithPin('vault code', '4821'), 4);
line('Brute force 4-digit PIN', "found {$bf['pin']} after {$bf['attempts']} tries in " . round($bf['seconds'], 3) . 's ' . $check($bf['pin'] === '4821'));

$secret = substr(bin2hex(random_bytes(2)), 0, 3);
$sc     = SideChannel::attack($secret);
line('Timing attack (3 hex chars)', "secret=$secret recovered={$sc['recovered']} " . ($sc['success'] ? ok(true) : "\033[33m(noisy run, try again)\033[0m"));

$ecb = Cryptanalysis::ecbVsCbc(str_repeat('ATTACK AT DAWN!!', 3), KeyManager::generateKey());
line('ECB leaks repeated blocks', $check(count(Cryptanalysis::repeatedBlocks($ecb['ecbBlocks'])) > 0 && count(Cryptanalysis::repeatedBlocks($ecb['cbcBlocks'])) === 0));
$bd = Cryptanalysis::birthdayCollision('md5', 24);
line('Birthday collision (24-bit)', "'{$bd['inputA']}' & '{$bd['inputB']}' after {$bd['tries']} tries " . $check($bd['found']));

$bm = new BackdooredMessenger($keyManager);
line('Backdoor (key escrow)', $check($bm->agencyDecrypt($bm->encrypt('private note', KeyManager::generateKey())) === 'private note'));

echo "\n" . ($allPassed ? "\033[1;32mAll demos ran successfully.\033[0m" : "\033[1;31mSome demos failed — see above.\033[0m") . "\n\n";
exit($allPassed ? 0 : 1);
