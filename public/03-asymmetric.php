<?php
/**
 * Lesson 03 — Asymmetric (public-key) encryption
 * Code used: src/AsymmetricCiphers.php
 */

require __DIR__ . '/../src/bootstrap.php';

/** Load the saved RSA key pair, or create it the first time (stored by the Key Manager). */
function rsaKeys(KeyManager $km, bool $regenerate = false): array
{
    if ($regenerate || $km->loadPem('rsa-private') === null) {
        $pair = AsymmetricCiphers::rsaGenerateKeyPair(2048);
        $km->savePem('rsa-private', $pair['private']);
        $km->savePem('rsa-public', $pair['public']);
    }
    return ['private' => $km->loadPem('rsa-private'), 'public' => $km->loadPem('rsa-public')];
}

$message = post('message', 'My OTP is 482193');
$out     = [];
$error   = null;

try {
    $rsa = rsaKeys($keyManager, action() === 'rsa-new');

    switch (action()) {
        case 'rsa-new':
            $out['newKeys'] = true;
            break;

        case 'rsa-encrypt':
            $out['rsaCipher']    = AsymmetricCiphers::rsaEncrypt($message, $rsa['public']);
            $out['rsaDecrypted'] = AsymmetricCiphers::rsaDecrypt($out['rsaCipher'], $rsa['private']);
            break;

        case 'rsa-sign':
            $out['signature'] = AsymmetricCiphers::sign($message, $rsa['private']);
            $out['tampered']  = post('tamper') === '1';
            $out['checked']   = $out['tampered'] ? $message . ' (edited)' : $message;
            $out['valid']     = AsymmetricCiphers::verify($out['checked'], $out['signature'], $rsa['public']);
            break;

        case 'dh':
            $out['dh']     = AsymmetricCiphers::toyDiffieHellman((int) post('p', '23'), (int) post('g', '5'));
            $out['x25519'] = AsymmetricCiphers::x25519Demo();
            break;

        case 'ecc':
            [$alice, $out['ecMs']]        = timed(fn () => AsymmetricCiphers::ecGenerateKeyPair());
            $bob                           = AsymmetricCiphers::ecGenerateKeyPair();
            [$rsa3072, $out['rsa3072Ms']] = timed(fn () => AsymmetricCiphers::rsaGenerateKeyPair(3072));
            $out['alice']   = $alice;
            $out['rsa3072'] = $rsa3072;
            // ECDSA = the elliptic-curve Digital Signature Standard (DSS)
            $out['ecSig']   = AsymmetricCiphers::sign($message, $alice['private']);
            $out['ecValid'] = AsymmetricCiphers::verify($message, $out['ecSig'], $alice['public']);
            // ECDH: both sides compute the same key without ever sending it
            $out['aliceShared'] = AsymmetricCiphers::ecdhSharedKey($alice['private'], $bob['public']);
            $out['bobShared']   = AsymmetricCiphers::ecdhSharedKey($bob['private'], $alice['public']);
            $out['ecdhCipher']  = EncryptionEngine::encrypt($message, $out['aliceShared']);
            $out['ecdhPlain']   = EncryptionEngine::decrypt($out['ecdhCipher'], $out['bobShared']);
            break;

        case 'elgamal':
            $keys           = AsymmetricCiphers::toyElGamalKeys();
            $out['egKeys']  = $keys;
            $out['egPairs'] = AsymmetricCiphers::toyElGamalEncrypt($message, $keys);
            $out['egPlain'] = AsymmetricCiphers::toyElGamalDecrypt($out['egPairs'], $keys['x'], $keys['p']);
            break;

        case 'benchmark':
            $out['bench'] = AsymmetricCiphers::benchmark(200);
            break;
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

page_header('03 · Asymmetric (Public-Key) Encryption', 'Two linked keys: a public one you share with everyone, and a private one you never share.');

lesson_intro(
    [
        'create an RSA key pair and send a secret message with it',
        'sign a message so anyone can check it really came from you',
        'agree on a secret key with someone while everyone is listening (Diffie-Hellman)',
        'see why ECC keys are so much smaller than RSA keys',
        'measure why real systems combine asymmetric <i>and</i> symmetric encryption',
    ],
    [
        'Public key'  => 'Shared openly with everyone. Used to <b>encrypt</b> messages to you, or to <b>check</b> your signatures.',
        'Private key' => 'Kept secret by its owner. Used to <b>decrypt</b> messages, or to <b>sign</b>.',
        'Key pair'    => 'A public key and a private key that are mathematically linked.',
        'Digital signature' => 'Proof, made with a private key, that a message came from its owner and wasn\'t changed.',
    ]
);
?>

<?php if ($error): notice('Error: ' . h($error), 'error'); endif; ?>

<?php step_start(1, 'The idea: a mailbox with a slot', 'idea'); ?>
    <p>Picture a mailbox with a slot. <b>Anyone</b> can drop a letter in (that's the <b>public key</b>), but only the owner has the key that opens the box (the <b>private key</b>).</p>
    <div class="flow">
        <span class="box plain">Message</span><span class="arrow">→ Bob's PUBLIC key →</span>
        <span class="box cipher">Ciphertext</span><span class="arrow">→ Bob's PRIVATE key →</span>
        <span class="box plain">Message</span>
    </div>
    <p>This solves the symmetric problem from lesson 02: there's no shared secret to sneak to the other person. Bob publishes his public key, and that's all anyone needs to write to him.</p>
    <p>It also works the other way around: something "locked" with the <b>private</b> key can be opened by anyone with the <b>public</b> key. That proves who locked it. It's called a <b>digital signature</b> (step 3).</p>
    <?php remember('public key = anyone can lock / check. Private key = only the owner can unlock / sign.'); ?>
<?php step_end(); ?>

<?php step_start(2, 'Send a secret with RSA', 'rsa',
    'RSA (named after its inventors Rivest, Shamir and Adleman) is the best-known public-key algorithm. It\'s used in HTTPS, SSH and email encryption.'); ?>
    <?php todo([
        'Open <b>"Show my key pair"</b> below and look at the two keys. Notice how much longer the private key is.',
        'Type a short message and press <b>Encrypt with the public key</b>.',
    ]); ?>
    <details class="hint">
        <summary>Show my key pair</summary>
        <div>
            <h3>Public key: safe to share with anyone</h3>
            <pre><?= h($rsa['public'] ?? '') ?></pre>
            <h3>Private key: never share (saved in storage/keys/rsa-private.pem)</h3>
            <pre><?= h(shorten($rsa['private'] ?? '', 400)) ?></pre>
        </div>
    </details>
    <form method="post">
        <label for="m1">Short message (RSA can only encrypt about 200 characters at once)</label>
        <input type="text" id="m1" name="message" value="<?= h($message) ?>">
        <button name="action" value="rsa-encrypt">Encrypt with the public key</button>
        <button name="action" value="rsa-new" class="secondary">Make a new key pair</button>
    </form>
    <?php if (isset($out['newKeys'])): notice('A brand-new 2048-bit RSA key pair was created.', 'success'); endif; ?>
    <?php if (isset($out['rsaCipher'])): ?>
        <div class="output">
            <?php row('Encrypted with the PUBLIC key', $out['rsaCipher'], 'bad'); ?>
            <?php row('Decrypted with the PRIVATE key', $out['rsaDecrypted'], 'good'); ?>
            <?php explain('Anyone could have created that ciphertext, because the public key is public. Only the holder of the <b>private key</b> could turn it back into your message. RSA is secure because multiplying two huge prime numbers is easy, but working backwards to find them (factoring) would take longer than the age of the universe.'); ?>
            <?php challenge(['Press Encrypt again with the same message. The ciphertext changes, because RSA adds randomness too.', 'Type a very long message (300+ characters). What error do you get, and why?']); ?>
        </div>
    <?php endif; ?>
    <?php code_ref('src/AsymmetricCiphers.php', '<code>rsaGenerateKeyPair()</code>, <code>rsaEncrypt()</code>, <code>rsaDecrypt()</code>.'); ?>
<?php step_end(); ?>

<?php step_start(3, 'Sign a message: proving who sent it', 'sign'); ?>
    <?php todo([
        'Press <b>Sign & check</b>. The signature should be valid.',
        'Now tick <b>"Someone edits the message after it was signed"</b> and press again.',
    ]); ?>
    <form method="post">
        <input type="hidden" name="action" value="rsa-sign">
        <label for="m2">Message to sign</label>
        <input type="text" id="m2" name="message" value="<?= h($message) ?>">
        <div class="checks"><label><input type="checkbox" name="tamper" value="1" <?= post('tamper') === '1' ? 'checked' : '' ?>> Someone edits the message after it was signed</label></div>
        <button>Sign & check</button>
    </form>
    <?php if (isset($out['signature'])): ?>
        <div class="output">
            <?php row('Signature (made with the PRIVATE key)', $out['signature']); ?>
            <?php row('Message being checked', $out['checked']); ?>
            <?php row('Is the signature valid?', $out['valid'] ? 'YES: it came from the key owner and was not changed' : 'NO: the message was changed (or signed by someone else)', $out['valid'] ? 'good' : 'bad'); ?>
            <?php explain($out['tampered']
                ? 'The message was changed by just a few characters and the check <b>failed</b>. A signature is tied to the exact content, so any edit breaks it.'
                : 'The signature was made with the <b>private</b> key, which only the owner has, and checked with the <b>public</b> key, which anyone has. If it\'s valid, the message really came from the owner and wasn\'t changed. Banks, software updates and government e-documents rely on this.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('encrypt with someone\'s PUBLIC key for secrecy. Sign with your own PRIVATE key for proof.'); ?>
<?php step_end(); ?>

<?php step_start(4, 'Agree on a secret while everyone listens (Diffie-Hellman)', 'dh',
    'Alice and Bob want a shared secret key, but every message between them can be read by eavesdroppers. Diffie-Hellman makes that possible. We use tiny numbers so you can follow the math on a calculator.'); ?>
    <?php todo(['Keep p = 23 and g = 5 (these are public), and press <b>Run the exchange</b>.', 'Check the bottom row: did Alice and Bob end up with the same number?']); ?>
    <form method="post">
        <input type="hidden" name="action" value="dh">
        <div class="inline">
            <div><label for="p">Prime number p (public)</label><input type="number" id="p" name="p" value="<?= h(post('p', '23')) ?>" min="5" max="100000"></div>
            <div><label for="g">Base g (public)</label><input type="number" id="g" name="g" value="<?= h(post('g', '5')) ?>" min="2" max="1000"></div>
            <button>Run the exchange</button>
        </div>
    </form>
    <?php if (isset($out['dh'])): $d = $out['dh']; ?>
        <div class="output table-wrap">
            <table>
                <tr><th></th><th>Alice</th><th>Bob</th></tr>
                <tr><td>1. Picks a secret number</td><td>a = <?= $d['alicePrivate'] ?> (secret)</td><td>b = <?= $d['bobPrivate'] ?> (secret)</td></tr>
                <tr><td>2. Sends a public value</td><td>A = <?= $d['g'] ?><sup><?= $d['alicePrivate'] ?></sup> mod <?= $d['p'] ?> = <b><?= $d['alicePublic'] ?></b> (public)</td><td>B = <?= $d['g'] ?><sup><?= $d['bobPrivate'] ?></sup> mod <?= $d['p'] ?> = <b><?= $d['bobPublic'] ?></b> (public)</td></tr>
                <tr><td>3. Computes the shared secret</td><td>B<sup>a</sup> mod p = <b><?= $d['aliceSecret'] ?></b></td><td>A<sup>b</sup> mod p = <b><?= $d['bobSecret'] ?></b></td></tr>
            </table>
            <?php if ($d['aliceSecret'] === $d['bobSecret']): ?>
                <?php explain('Both got <b>' . $d['aliceSecret'] . '</b> without ever sending it! An eavesdropper saw only p, g, A and B. To find the secret, they\'d need a or b, which means solving a "discrete logarithm". With tiny numbers that\'s easy, but real systems use numbers hundreds of digits long, which makes it practically impossible. ("mod" means "the remainder after dividing", like the hours on a clock.)'); ?>
            <?php else: ?>
                <?php notice('The results differ: p must be a <b>prime</b> number. Try 23, 47 or 97.', 'warn'); ?>
            <?php endif; ?>
            <h3>The real-world version: X25519 (used in WhatsApp, Signal and modern HTTPS)</h3>
            <?php row("Alice's public value", $out['x25519']['alicePublic']); ?>
            <?php row("Bob's public value", $out['x25519']['bobPublic']); ?>
            <?php row('Alice computes', $out['x25519']['aliceShared'], 'good'); ?>
            <?php row('Bob computes', $out['x25519']['bobShared'], 'good'); ?>
            <?php challenge(['Run it several times. The secrets change, but Alice and Bob always match.', 'Try p = 10 (not a prime). What happens?']); ?>
        </div>
    <?php endif; ?>
<?php step_end(); ?>

<?php step_start(5, 'ECC: the same security with much smaller keys', 'ecc',
    'Elliptic Curve Cryptography (ECC) uses a different kind of math (points on a curve). It offers the same security as RSA with far shorter keys, which is great for phones and small "Internet of Things" devices.'); ?>
    <?php todo(['Press the button. It creates an ECC key and an equally strong RSA key.', 'Compare the key sizes and creation times in the table.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="ecc">
        <input type="hidden" name="message" value="<?= h($message) ?>">
        <button>Compare ECC and RSA</button>
    </form>
    <?php if (isset($out['alice'])): ?>
        <div class="output">
            <table>
                <tr><th>Key type</th><th>Strength</th><th>Public key size</th><th>Time to create</th></tr>
                <tr><td><b>ECC P-256</b></td><td>≈128-bit</td><td><?= strlen($out['alice']['public']) ?> characters</td><td><?= number_format($out['ecMs'], 1) ?> ms</td></tr>
                <tr><td><b>RSA-3072</b></td><td>≈128-bit</td><td><?= strlen($out['rsa3072']['public']) ?> characters</td><td><?= number_format($out['rsa3072Ms'], 1) ?> ms</td></tr>
            </table>
            <?php explain('Same strength, but the ECC key is several times smaller and was created much faster. Less data and less computing power is why ECC suits phones and small devices.'); ?>
            <h3>ECC can also sign (ECDSA, part of the Digital Signature Standard)…</h3>
            <?php row('ECDSA signature', $out['ecSig']); ?>
            <?php row('Valid?', $out['ecValid'] ? 'yes' : 'no', $out['ecValid'] ? 'good' : 'bad'); ?>
            <h3>…and agree on a key, like Diffie-Hellman (ECDH)</h3>
            <?php row("Alice's computed key", hex($out['aliceShared'])); ?>
            <?php row("Bob's computed key", hex($out['bobShared']), $out['aliceShared'] === $out['bobShared'] ? 'good' : 'bad'); ?>
            <?php row('Alice → Bob, encrypted with AES using that key', $out['ecdhCipher'], 'bad'); ?>
            <?php row('Bob decrypts', $out['ecdhPlain'], 'good'); ?>
        </div>
    <?php endif; ?>
    <?php remember('ECC gives the same security as RSA with much smaller keys.'); ?>
<?php step_end(); ?>

<?php step_start(6, 'ElGamal: one more public-key cipher (toy size)', 'elgamal',
    'ElGamal is built on the same math as Diffie-Hellman. Like step 4, this uses small numbers so you can see what\'s going on.'); ?>
    <?php todo(['Type a short word and press the button.', 'Look at the ciphertext: every single character became a <b>pair</b> of numbers.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="elgamal">
        <label for="m3">Short message</label>
        <input type="text" id="m3" name="message" value="<?= h(substr($message, 0, 20)) ?>" maxlength="40">
        <button>Encrypt & decrypt with ElGamal</button>
    </form>
    <?php if (isset($out['egKeys'])): $k = $out['egKeys']; ?>
        <div class="output">
            <?php row('Public key (p, g, y)', "p={$k['p']}, g={$k['g']}, y={$k['y']}"); ?>
            <?php row('Private key x', (string) $k['x']); ?>
            <?php row('Ciphertext: one (c1, c2) pair per character', implode(' ', array_map(fn ($p) => "({$p[0]},{$p[1]})", $out['egPairs'])), 'bad'); ?>
            <?php row('Decrypted', $out['egPlain'], 'good'); ?>
            <?php explain('A fresh random number is used for every character, so even repeated letters (like the two "l"s in "hello") encrypt differently. The trade-off: the ciphertext is twice as big as the message.'); ?>
        </div>
    <?php endif; ?>
<?php step_end(); ?>

<?php step_start(7, 'Which is faster: symmetric or asymmetric?', 'speed'); ?>
    <?php todo(['Press the button. It encrypts and decrypts the same short message 200 times with AES and with RSA.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="benchmark">
        <button>Run the race</button>
    </form>
    <?php if (isset($out['bench'])): $b = $out['bench']; ?>
        <div class="output">
            <table>
                <tr><th></th><th>AES-256 (symmetric)</th><th>RSA-2048 (asymmetric)</th></tr>
                <tr><td>Making a key</td><td><?= number_format($b['aesKeygenMs'], 3) ?> ms</td><td><?= number_format($b['rsaKeygenMs'], 1) ?> ms</td></tr>
                <tr><td><?= $b['rounds'] ?> × encrypt + decrypt</td><td><?= number_format($b['aesMs'], 1) ?> ms</td><td><?= number_format($b['rsaMs'], 1) ?> ms</td></tr>
            </table>
            <?php explain('RSA was about <b>' . round($b['times']) . '× slower</b>. So real systems use <b>both</b> ("hybrid encryption"): public-key crypto to safely share a random AES key, then fast AES for all the actual data. That\'s exactly how HTTPS works. You\'ll see it in lesson 06.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('asymmetric solves key sharing, symmetric does the heavy lifting. Together = hybrid.'); ?>
<?php step_end(); ?>

<?php check_yourself([
    ['You want to send Bob a secret. Which key do you encrypt with?', ['Your private key', 'Bob\'s public key', 'Bob\'s private key'], 1,
        'Anyone can use Bob\'s public key, but only Bob\'s private key can decrypt.'],
    ['What does a valid digital signature prove?', ['The message is encrypted', 'The message came from the private-key owner and was not changed', 'The message is short'], 1,
        'Only the private key can create it; anyone can check it with the public key.'],
    ['Why is ECC popular on phones and IoT devices?', ['It needs no keys', 'Same security with much smaller keys and less computing power', 'It is a symmetric cipher'], 1,
        'A 256-bit ECC key ≈ a 3072-bit RSA key.'],
    ['Why do real systems combine RSA/ECC with AES?', ['Asymmetric is slow, so it\'s used only to share an AES key; AES encrypts the data', 'AES is insecure on its own', 'It\'s required by law'], 0,
        'This is called hybrid encryption, used in HTTPS.'],
]); ?>

<?php page_footer(); ?>
