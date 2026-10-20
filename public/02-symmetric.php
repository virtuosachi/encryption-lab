<?php
/**
 * Lesson 02 — Symmetric encryption
 * Code used: src/SymmetricCiphers.php
 */

require __DIR__ . '/../src/bootstrap.php';

$algorithms = array_keys(SymmetricCiphers::ALGORITHMS); // ['AES-256', 'DES', ...]
$plaintext  = post('plaintext', 'Transfer ₱5,000 to account 0012-3456');
$compare    = null;
$tryIt      = ['algo' => post('algo', 'AES-256'), 'key' => post('key'), 'ciphertext' => post('ciphertext')];
$error      = null;

/** Convert the hex key typed in the form to bytes, with a friendly error for bad input. */
function keyFromHex(string $hexKey): string
{
    if ($hexKey === '' || strlen($hexKey) % 2 !== 0 || !ctype_xdigit($hexKey)) {
        throw new InvalidArgumentException('The key must be hexadecimal (0-9, a-f). Press "Make a random key" first.');
    }
    return hex2bin($hexKey);
}

try {
    switch (action()) {
        case 'gen-key':
            $tryIt['key']        = hex(SymmetricCiphers::generateKey($tryIt['algo']));
            $tryIt['ciphertext'] = '';
            $tryIt['did']        = 'key';
            break;

        case 'encrypt':
            $tryIt['ciphertext'] = SymmetricCiphers::encrypt($tryIt['algo'], $plaintext, keyFromHex($tryIt['key']));
            $tryIt['did']        = 'encrypt';
            break;

        case 'decrypt':
            $tryIt['did']       = 'decrypt';
            $tryIt['decrypted'] = SymmetricCiphers::decrypt($tryIt['algo'], $tryIt['ciphertext'], keyFromHex($tryIt['key']));
            break;

        // Run the same message through ALL five algorithms.
        case 'compare':
            $compare = [];
            foreach ($algorithms as $algo) {
                $key = SymmetricCiphers::generateKey($algo);
                [$ciphertext, $encMs] = timed(fn () => SymmetricCiphers::encrypt($algo, $plaintext, $key));
                [$decrypted, $decMs]  = timed(fn () => SymmetricCiphers::decrypt($algo, $ciphertext, $key));
                $compare[$algo] = compact('key', 'ciphertext', 'decrypted', 'encMs', 'decMs');
            }
            break;
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

$statusClass = fn (string $s) => match (true) {
    str_starts_with($s, 'Recommended'), str_starts_with($s, 'Secure') => 'good',
    $s === 'Broken' => 'bad',
    default => 'warn',
};

page_header('02 · Symmetric Encryption', 'One shared secret key both locks and unlocks the data.');

lesson_intro(
    [
        'create your own secret key and use it to encrypt',
        'see that only that <b>same</b> key can decrypt',
        'compare five symmetric algorithms: AES, DES, 3DES, Blowfish and Twofish',
        'learn why DES is outdated and AES is today\'s standard',
    ],
    [
        'Symmetric'   => 'The <b>same</b> key is used to encrypt and to decrypt. Also called a "shared secret".',
        'Key length'  => 'How many bits the key has. Every extra bit doubles the number of possible keys.',
        'Block cipher'=> 'An algorithm that scrambles data in fixed-size chunks (blocks), e.g. 16 bytes at a time for AES.',
        'Hex'         => 'A way to write bytes with 0–9 and a–f. Two hex characters = 1 byte = 8 bits.',
    ]
);
?>

<?php step_start(1, 'The idea: one key, two jobs', 'idea'); ?>
    <div class="flow">
        <span class="box plain">Message</span><span class="arrow">→ key →</span>
        <span class="box cipher">Ciphertext</span><span class="arrow">→ same key →</span>
        <span class="box plain">Message</span>
    </div>
    <p>Think of a padlock with one key that both locks and unlocks it. If you want a friend to open your box, you need to give them a copy of the key.</p>
    <ul>
        <li><b>Good:</b> it's very fast, so it's used for almost all bulk data (files, disks, Wi-Fi, video calls).</li>
        <li><b>Problem:</b> how do you get the key to your friend safely? If someone copies it on the way, they can read everything. Lesson 03 solves this.</li>
    </ul>
    <?php remember('symmetric = one shared key. Fast, but the key must be shared safely.'); ?>
<?php step_end(); ?>

<?php step_start(2, 'Make a key and encrypt with it', 'try'); ?>
    <?php todo([
        'Keep <b>AES-256</b> selected and press <b>Make a random key</b>.',
        'Type a message (or keep the example) and press <b>Encrypt</b>.',
        'The ciphertext appears in the last box. Continue to step 3.',
    ]); ?>
    <form method="post">
        <div class="inline">
            <div>
                <label for="algo">Algorithm</label>
                <select id="algo" name="algo">
                    <?php foreach ($algorithms as $a): ?>
                        <option <?= $tryIt['algo'] === $a ? 'selected' : '' ?>><?= h($a) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button name="action" value="gen-key" class="secondary">Make a random key</button>
        </div>
        <label for="key">Secret key (hex)</label>
        <input type="text" id="key" name="key" value="<?= h($tryIt['key']) ?>" placeholder="press “Make a random key”">
        <label for="p2">Message</label>
        <textarea id="p2" name="plaintext"><?= h($plaintext) ?></textarea>
        <button name="action" value="encrypt">Encrypt</button>
        <label for="ct">Ciphertext (base64)</label>
        <textarea id="ct" name="ciphertext" placeholder="appears here after Encrypt"><?= h($tryIt['ciphertext']) ?></textarea>
        <button name="action" value="decrypt">Decrypt</button>
    </form>

    <?php if ($error): notice('Error: ' . h($error), 'error'); endif; ?>

    <?php if (($tryIt['did'] ?? '') === 'key'): ?>
        <?php explain('You made a <b>' . (strlen($tryIt['key']) * 4) . '-bit</b> key (' . strlen($tryIt['key']) . ' hex characters × 4 bits). It came from your computer\'s secure random-number generator, so nobody could guess it. Now press <b>Encrypt</b>.'); ?>
    <?php elseif (($tryIt['did'] ?? '') === 'encrypt'): ?>
        <?php explain('Your message was scrambled with ' . h($tryIt['algo']) . ' and your key. Anyone who sees the ciphertext but doesn\'t have the key learns nothing. Now go to step 3.'); ?>
    <?php elseif (($tryIt['did'] ?? '') === 'decrypt' && isset($tryIt['decrypted'])): ?>
        <div class="output"><?php row('Decrypted message', $tryIt['decrypted'], 'good'); ?></div>
        <?php explain('The <b>same key</b> that encrypted the message decrypted it. That\'s what makes it symmetric.'); ?>
    <?php elseif (($tryIt['did'] ?? '') === 'decrypt' && $error): ?>
        <?php explain('Decryption failed because the key isn\'t the one used to encrypt. Even a one-character difference makes it a completely different key.'); ?>
    <?php endif; ?>
    <?php code_ref('src/SymmetricCiphers.php', '<code>generateKey()</code> and <code>encrypt()</code>.'); ?>
<?php step_end(); ?>

<?php step_start(3, 'Decrypt it, then break the key on purpose', 'decrypt'); ?>
    <?php todo([
        'Back in step 2, press <b>Decrypt</b>. You get your message back.',
        'Now change <b>one character</b> of the key (e.g. the last letter) and press <b>Decrypt</b> again.',
        'Finally, switch the algorithm to <b>DES</b>, make a new key and notice how much <b>shorter</b> it is.',
    ]); ?>
    <?php hint('If the key box says it must be hexadecimal, you typed a letter after "f". Only 0–9 and a–f are allowed.'); ?>
    <?php remember('only the exact same key decrypts. Change one bit and it\'s a completely different key.'); ?>
<?php step_end(); ?>

<?php step_start(4, 'Compare five symmetric algorithms', 'compare',
    'There are many symmetric algorithms. Some are modern, some are retired. Let\'s run one message through five of them.'); ?>
    <table>
        <tr><th>Algorithm</th><th>Key length</th><th>Block size</th><th>Status today</th><th>About it</th></tr>
        <?php foreach (SymmetricCiphers::ALGORITHMS as $name => $info): ?>
            <tr>
                <td><b><?= h($name) ?></b></td>
                <td><?= $info['keyBytes'] * 8 ?> bits</td>
                <td><?= $info['blockBytes'] * 8 ?> bits</td>
                <td><span class="badge <?= $statusClass($info['status']) ?>"><?= h($info['status']) ?></span></td>
                <td class="explain"><?= h($info['note']) ?></td>
            </tr>
        <?php endforeach; ?>
    </table>
    <?php todo(['Press the button to encrypt and decrypt the same message with all five.', 'Compare the ciphertext lengths and the times.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="compare">
        <label for="p1">Message</label>
        <textarea id="p1" name="plaintext"><?= h($plaintext) ?></textarea>
        <button>Run all five</button>
    </form>

    <?php if ($compare): ?>
        <div class="output table-wrap">
            <table>
                <tr><th>Algorithm</th><th>Random key (hex)</th><th>Ciphertext</th><th>Decrypted OK?</th><th>Time</th></tr>
                <?php foreach ($compare as $algo => $r): ?>
                    <tr>
                        <td><b><?= h($algo) ?></b></td>
                        <td><code><?= h(hex($r['key'])) ?></code></td>
                        <td><code><?= h($r['ciphertext']) ?></code></td>
                        <td><?= $r['decrypted'] === $plaintext ? 'yes' : 'no' ?></td>
                        <td><?= number_format($r['encMs'], 3) ?> ms</td>
                    </tr>
                <?php endforeach; ?>
            </table>
            <?php explain('All five scrambled and recovered your message, but they aren\'t equally safe:
                <ul>
                    <li><b>DES</b> keys are tiny: only 56 of their 64 bits are real key bits. A modern computer cluster can try every possible DES key in hours. That\'s why it was replaced.</li>
                    <li><b>3DES</b> runs DES three times to make up for that. Safer, but slow, and now retired.</li>
                    <li><b>AES</b> replaced DES as the standard. A 256-bit key has more possible values than there are atoms in the observable universe.</li>
                    <li><b>Blowfish</b> and <b>Twofish</b> are free, open-source designs. Twofish (128-bit blocks, up to 256-bit keys) is still considered secure.</li>
                </ul>
                Times differ partly because DES, Blowfish and Twofish run here as plain PHP code, while AES uses fast built-in OpenSSL code.'); ?>
            <?php challenge([
                'Look at the ciphertext lengths. The 8-byte-block ciphers (DES, 3DES, Blowfish) grow in smaller steps than the 16-byte ones (AES, Twofish).',
                'Encrypt a very long message (paste a paragraph a few times). Which algorithm is fastest?',
            ]); ?>
        </div>
    <?php endif; ?>
    <?php remember('AES is today\'s go-to symmetric cipher. DES is retired because its key is too short.'); ?>
<?php step_end(); ?>

<?php check_yourself([
    ['In symmetric encryption, how many keys are used?', ['One shared key', 'Two different keys', 'No key'], 0,
        'The same key both encrypts and decrypts.'],
    ['What is the biggest challenge with symmetric encryption?', ['It is too slow', 'Sharing the key safely with the other person', 'It only works on numbers'], 1,
        'Anyone who intercepts the key can read everything. Lesson 03 solves this.'],
    ['Why is DES considered outdated?', ['Its key is too short and can be brute-forced', 'It is too slow', 'It can\'t decrypt'], 0,
        'Only 56 real key bits, so all possible keys can be tried.'],
    ['Which algorithm is the modern standard?', ['DES', 'AES', 'Blowfish'], 1,
        'AES is used in HTTPS, Wi-Fi, phones and disk encryption.'],
]); ?>

<?php page_footer(); ?>
