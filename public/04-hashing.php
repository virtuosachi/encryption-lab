<?php
/**
 * Lesson 04 — Cryptographic hashing
 * Code used: src/Hashing.php
 */

require __DIR__ . '/../src/bootstrap.php';

$input = post('input', 'Hello, world!');
$out   = [];
$error = null;

try {
    switch (action()) {
        case 'hash':
            $out['all']           = Hashing::hashAll($input);
            $out['deterministic'] = Hashing::isDeterministic($input);
            break;

        case 'avalanche':
            $out['avalanche'] = Hashing::avalanche(post('a'), post('b'));
            break;

        case 'integrity':
            $out['integrity'] = Hashing::verifyIntegrity(post('file'), post('expected'));
            $out['actual']    = Hashing::hash('sha256', post('file'));
            break;

        case 'password':
            $out['pwHash']  = Hashing::hashPassword(post('password'));
            $out['pwHash2'] = Hashing::hashPassword(post('password'));
            $out['pwOk']    = Hashing::checkPassword(post('login'), $out['pwHash']);
            break;
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

// Small spelling differences -> completely different hashes.
$variants = ['Hello, world!', 'Hello world!', 'hello world!', 'Hello, World!', "Hello, world!\n"];

page_header('04 · Hashing', 'One-way "fingerprints" for data: no key, no way back, always the same length.');

lesson_intro(
    [
        'make fingerprints (hashes) of any text with six algorithms',
        'discover the four properties every good hash must have',
        'see a one-letter change completely transform a hash',
        'use a hash to catch a modified file, and store passwords safely',
    ],
    [
        'Hash / digest' => 'A short, fixed-length fingerprint calculated from any data.',
        'One-way'       => 'Easy to compute from the data, impossible to turn back into the data. There\'s no "unhash".',
        'Collision'     => 'Two different inputs that produce the same hash. Good hashes make this practically impossible.',
        'Bit'           => 'A single 0 or 1. Each hex character stands for 4 bits.',
    ]
);
?>

<?php if ($error): notice('Error: ' . h($error), 'error'); endif; ?>

<?php step_start(1, 'The idea: a fingerprint, not a lock', 'idea'); ?>
    <p>Encryption is a <b>lock</b>: with the key, you get the data back. Hashing is a <b>fingerprint</b>: it identifies the data, but you can't rebuild a person from their fingerprint.</p>
    <div class="flow">
        <span class="box plain">Any data<br><small>1 letter or 1 GB</small></span><span class="arrow">→ hash function →</span>
        <span class="box">Fixed-size fingerprint</span><span class="arrow">(no way back)</span>
    </div>
    <p>Hashes are used to check that files weren't changed, to store passwords, and inside digital signatures and blockchains.</p>
    <?php remember('hashing uses no key and can\'t be reversed. Encryption can.'); ?>
<?php step_end(); ?>

<?php step_start(2, 'Hash some text with six algorithms', 'hash'); ?>
    <?php todo([
        'Keep <code>Hello, world!</code> or type anything you like, then press <b>Hash it</b>.',
        'Look at the <b>Length</b> column, then hash a single letter. Does the length change?',
    ]); ?>
    <form method="post">
        <input type="hidden" name="action" value="hash">
        <label for="in">Input</label>
        <textarea id="in" name="input"><?= h($input) ?></textarea>
        <button>Hash it</button>
    </form>
    <?php if (isset($out['all'])): ?>
        <div class="output table-wrap">
            <table>
                <tr><th>Algorithm</th><th>Hash (hex)</th><th>Length</th><th>Bits</th><th>Time</th></tr>
                <?php foreach ($out['all'] as $r): ?>
                    <tr>
                        <td><b><?= h($r['label']) ?></b><br><small class="explain"><?= h($r['note']) ?></small></td>
                        <td><code><?= h($r['digest']) ?></code></td>
                        <td><?= $r['chars'] ?> chars</td>
                        <td><?= $r['chars'] ?> × 4 = <?= $r['bits'] ?></td>
                        <td><?= number_format($r['ms'], 4) ?> ms</td>
                    </tr>
                <?php endforeach; ?>
            </table>
            <?php explain('Every algorithm gave a fixed-length result, whatever the input length. Each hex character holds 4 bits, so a 64-character SHA-256 hash = 64 × 4 = <b>256 bits</b>, and a 32-character MD5 hash = <b>128 bits</b>. These four properties are what make a hash function good:'); ?>
            <div class="grid">
                <div class="mini"><h3>Efficient</h3>Each hash took a tiny fraction of a millisecond.</div>
                <div class="mini"><h3>Deterministic <?= $out['deterministic'] ? '(yes)' : '(no)' ?></h3>Same input → same hash, every time. (We checked 5 times.)</div>
                <div class="mini"><h3>Preimage-resistant</h3>The hash reveals nothing about the input, and there's no "unhash" function.</div>
                <div class="mini"><h3>Collision-resistant</h3>It's practically impossible to find two inputs with the same hash (except for MD5 and SHA-1, which are now broken).</div>
            </div>
            <?php challenge(['Press <b>Hash it</b> again without changing anything. Are the results the same?', 'Hash a whole paragraph. Is SHA-256 still 64 characters?']); ?>
        </div>
    <?php endif; ?>
    <?php code_ref('src/Hashing.php', '<code>hashAll()</code>.'); ?>
<?php step_end(); ?>

<?php step_start(3, 'Change one character: the avalanche effect', 'avalanche'); ?>
    <?php todo(['Compare <code>Hello, world!</code> with <code>Hello, world?</code> (only the last character differs).', 'Then try your own pair, such as your name with and without a capital letter.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="avalanche">
        <div class="inline">
            <div><label for="a">Input A</label><input type="text" id="a" name="a" value="<?= h(post('a', 'Hello, world!')) ?>"></div>
            <div><label for="b">Input B</label><input type="text" id="b" name="b" value="<?= h(post('b', 'Hello, world?')) ?>"></div>
            <button>Compare</button>
        </div>
    </form>
    <?php if (isset($out['avalanche'])): $a = $out['avalanche']; ?>
        <div class="output">
            <?php row('SHA-256 of A', $a['hashA']); ?>
            <?php row('SHA-256 of B', $a['hashB']); ?>
            <?php row('Bits that changed', "{$a['changedBits']} of {$a['totalBits']} ({$a['percent']}%)", 'good'); ?>
            <?php explain($a['changedBits'] === 0
                ? 'The inputs are identical, so the hashes are identical: that\'s determinism.'
                : 'A tiny input change flipped about <b>half</b> of all output bits. This "avalanche effect" means similar inputs give totally unrelated hashes, so you can\'t guess an input by tweaking it bit by bit.'); ?>
        </div>
    <?php endif; ?>
    <h3>Exactness matters</h3>
    <p class="explain">Hashes are computed on the <b>exact</b> characters. A comma, a capital letter or a hidden "new line" at the end changes everything:</p>
    <div class="table-wrap">
        <table>
            <tr><th>Exact input</th><th>SHA-256</th><th>MD5</th></tr>
            <?php foreach ($variants as $v): ?>
                <tr>
                    <td><code><?= h(json_encode($v)) ?></code></td>
                    <td><code><?= h(hash('sha256', $v)) ?></code></td>
                    <td><code><?= h(md5($v)) ?></code></td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>
    <?php remember('change anything, even one character, and the hash changes completely.'); ?>
<?php step_end(); ?>

<?php step_start(4, 'Catch a modified download', 'integrity',
    'Software websites publish the SHA-256 hash of their downloads. After downloading, you hash your copy and compare. If they match, nobody tampered with it on the way.'); ?>
    <?php todo([
        'Press <b>Check</b>: the "file" and the published hash match.',
        'Now change <b>one character</b> of the file content (pretend a hacker slipped in malware) and press <b>Check</b> again.',
    ]); ?>
    <form method="post">
        <input type="hidden" name="action" value="integrity">
        <label for="file">Downloaded "file" content</label>
        <textarea id="file" name="file"><?= h(post('file', 'installer-v1.2.exe contents')) ?></textarea>
        <label for="expected">Hash published on the official website (SHA-256)</label>
        <input type="text" id="expected" name="expected" value="<?= h(post('expected', hash('sha256', 'installer-v1.2.exe contents'))) ?>">
        <button>Check</button>
    </form>
    <?php if (isset($out['actual'])): ?>
        <div class="output">
            <?php row('Hash of your download', $out['actual']); ?>
            <?php row('Result', $out['integrity'] ? 'MATCH: the file is exactly the original' : 'MISMATCH: the file was changed or damaged', $out['integrity'] ? 'good' : 'bad'); ?>
            <?php explain($out['integrity']
                ? 'Your hash equals the published one, so the file is byte-for-byte identical to the original. Now try changing one character.'
                : 'Even a one-character change produced a completely different hash, so the tampering was caught. This is called checking <b>integrity</b>.'); ?>
        </div>
    <?php endif; ?>
<?php step_end(); ?>

<?php step_start(5, 'Storing passwords safely', 'passwords',
    'Websites should never store your actual password. They store a special, deliberately <b>slow</b> hash of it.'); ?>
    <?php todo(['Press <b>Sign up & log in</b>.', 'Then change the login attempt to a wrong password and press it again.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="password">
        <div class="inline">
            <div><label for="pw">Password at sign-up</label><input type="text" id="pw" name="password" value="<?= h(post('password', 'CorrectHorse42')) ?>"></div>
            <div><label for="login">Password typed at login</label><input type="text" id="login" name="login" value="<?= h(post('login', 'CorrectHorse42')) ?>"></div>
            <button>Sign up & log in</button>
        </div>
    </form>
    <?php if (isset($out['pwHash'])): ?>
        <div class="output">
            <?php row('What the website stores', $out['pwHash']); ?>
            <?php row('Same password, hashed a second time', $out['pwHash2']); ?>
            <?php row('Login allowed?', $out['pwOk'] ? 'yes' : 'no', $out['pwOk'] ? 'good' : 'bad'); ?>
            <?php explain('The two stored hashes are <b>different</b> even though the password is the same. A random "salt" is mixed in, so two users with the same password don\'t get matching hashes. When you log in, the site hashes what you typed with the same salt and compares. Your real password is never stored. The algorithm (bcrypt) is deliberately slow, so attackers can\'t try billions of guesses per second.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('passwords are hashed with a slow, salted algorithm. Never encrypt them, and never use plain MD5 or SHA.'); ?>
<?php step_end(); ?>

<?php check_yourself([
    ['Can you turn a SHA-256 hash back into the original text?', ['Yes, with the right key', 'No, hashing is one-way', 'Only for short texts'], 1,
        'Hashing has no key and no reverse operation.'],
    ['You hash a 1-letter word and a 500-page book with SHA-256. The hashes are…', ['Different lengths', 'Both 64 hex characters (256 bits)', 'Identical'], 1,
        'Hashes have a fixed length whatever the input size.'],
    ['Why is MD5 no longer recommended for security?', ['It is too slow', 'Collisions (two inputs, same hash) can be created easily', 'It produces 512-bit hashes'], 1,
        'MD5 is "cryptographically broken" because of collision attacks.'],
    ['How do you check that a downloaded file wasn\'t modified?', ['Encrypt it', 'Compare its hash with the one published by the official source', 'Rename it'], 1,
        'Matching hashes = identical file.'],
]); ?>

<?php page_footer(); ?>
