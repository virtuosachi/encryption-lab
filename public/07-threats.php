<?php
/**
 * Lesson 07 — Attacks on encryption
 * Code used: src/Threats.php
 *
 * Every attack here targets data this lab creates itself — it's a safe sandbox.
 */

require __DIR__ . '/../src/bootstrap.php';

$out   = [];
$error = null;

try {
    switch (action()) {
        case 'brute':
            $digits = max(1, min(6, (int) post('digits', '4')));          // clamp to 1..6
            $pin    = str_pad((string) random_int(0, 10 ** $digits - 1), $digits, '0', STR_PAD_LEFT);
            $pkg    = BruteForce::encryptWithPin(post('secret'), $pin);
            $res    = BruteForce::attack($pkg, $digits);
            $out['brute'] = ['pin' => $pin, 'pkg' => $pkg, 'res' => $res, 'digits' => $digits,
                             'estimates' => BruteForce::estimate($res['keysPerSec'] ?? 100000),
                             'estimatesCluster' => BruteForce::estimate(1e12)];
            break;

        case 'timing':
            $length = max(2, min(5, (int) post('length', '4')));
            $secret = substr(bin2hex(random_bytes(3)), 0, $length);
            [$attack, $ms] = timed(fn () => SideChannel::attack($secret));
            // Constant-time compare: a wrong first char vs a right first char take the same time.
            [, $safeWrong] = timed(fn () => SideChannel::safeCompare(str_repeat('x', $length), $secret));
            [, $safeRight] = timed(fn () => SideChannel::safeCompare($secret[0] . str_repeat('x', $length - 1), $secret));
            $out['timing'] = compact('secret', 'attack', 'ms', 'safeWrong', 'safeRight');
            break;

        case 'ecb':
            $out['ecb'] = Cryptanalysis::ecbVsCbc(post('ecbtext'), KeyManager::generateKey());
            break;

        case 'birthday':
            $bits = (int) post('bits', '24');
            $bits = in_array($bits, [16, 20, 24, 28, 32], true) ? $bits : 24;
            $out['birthday'] = Cryptanalysis::birthdayCollision(post('algo') === 'sha256' ? 'sha256' : 'md5', $bits);
            break;

        case 'backdoor':
            $messenger = new BackdooredMessenger($keyManager);
            $userKey   = KeyManager::generateKey();          // only the user is supposed to know this
            $packet    = $messenger->encrypt(post('privmsg'), $userKey);
            $out['backdoor'] = [
                'packet' => $packet,
                'user'   => EncryptionEngine::decrypt($packet['ciphertext'], $userKey),
                'agency' => $messenger->agencyDecrypt($packet),
            ];
            break;
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

/** Mark repeated ciphertext blocks so the ECB leak is visible. */
function blockList(array $blocks, array $repeated): string
{
    $html = '';
    foreach ($blocks as $i => $b) {
        $cls   = in_array($b, $repeated, true) ? 'hl' : '';
        $html .= '<div><small>block ' . ($i + 1) . '</small> <code class="' . $cls . '">' . h($b) . '</code></div>';
    }
    return $html;
}

page_header('07 · Attacks on Encryption', 'Think like an attacker to understand the defences. Every attack here targets data the lab creates itself.');

lesson_intro(
    [
        '<b>brute-force</b> a short PIN and see why long keys win',
        'steal a secret just by <b>timing</b> how long a computer takes to answer (a side channel)',
        'spot patterns in badly used encryption, and make hashes collide (<b>cryptanalysis</b>)',
        'see how a hidden <b>backdoor</b> can betray "secure" encryption',
    ],
    [
        'Brute force'  => 'Trying every possible key until one works.',
        'Key space'    => 'The number of possible keys. A 4-digit PIN has 10,000; AES-256 has 2<sup>256</sup>.',
        'Side channel' => 'Information leaking from <i>how</i> a system behaves (time, power, errors) rather than from the math.',
        'Backdoor'     => 'A secret way in, deliberately hidden in a system.',
    ]
);
?>

<?php if ($error): notice('Error: ' . h($error), 'error'); endif; ?>

<?php step_start(1, 'Brute force: try every key', 'brute',
    'The secret is encrypted with strong AES-256, but the key is made from a short number PIN. The attacker simply tries every PIN: 0000, 0001, 0002…'); ?>
    <?php todo([
        'Keep <b>4 digits</b> and press the button. The computer picks a random PIN, encrypts your secret, and then attacks it.',
        'Repeat with <b>5</b> and <b>6</b> digits. How does the time change?',
    ]); ?>
    <form method="post">
        <input type="hidden" name="action" value="brute">
        <div class="inline">
            <div><label>Secret to protect</label><input type="text" name="secret" value="<?= h(post('secret', 'Vault code: left 32, right 7, left 15')) ?>"></div>
            <div><label>PIN length (digits)</label>
                <select name="digits"><?php foreach ([2, 3, 4, 5, 6] as $d): ?><option <?= (int) post('digits', '4') === $d ? 'selected' : '' ?>><?= $d ?></option><?php endforeach; ?></select>
            </div>
            <button>Encrypt, then attack</button>
        </div>
    </form>
    <?php if (isset($out['brute'])): $b = $out['brute']; $r = $b['res']; ?>
        <div class="output">
            <?php row('The secret PIN (the attacker doesn\'t know it)', $b['pin']); ?>
            <?php row('Ciphertext the attacker stole', $b['pkg'], 'bad'); ?>
            <?php if ($r['found']): ?>
                <?php row('Attacker found the PIN', $r['pin'] . ' after ' . number_format($r['attempts']) . ' of ' . number_format($r['keyspace']) . ' possible PINs', 'bad'); ?>
                <?php row('Time it took', round($r['seconds'], 3) . ' seconds (' . number_format($r['keysPerSec']) . ' guesses per second on this computer)'); ?>
                <?php row('Recovered secret', $r['plaintext'], 'bad'); ?>
            <?php endif; ?>
            <?php explain('AES itself wasn\'t broken. The <b>key space</b> was just too small. Every extra digit makes it 10× harder, and every extra <b>bit</b> of a real key doubles the work. Look how fast the time explodes for real key lengths:'); ?>
            <table>
                <tr><th>Key length</th><th>Possible keys</th><th>This computer</th><th>Giant cluster (10¹² guesses/s)</th></tr>
                <?php foreach ($b['estimates'] as $i => $e): ?>
                    <tr><td><?= h($e['label']) ?></td><td>2<sup><?= $e['bits'] ?></sup> ≈ <?= h(sprintf('%.2e', $e['keys'])) ?></td><td><?= h($e['human']) ?></td><td><?= h($b['estimatesCluster'][$i]['human']) ?></td></tr>
                <?php endforeach; ?>
            </table>
            <?php challenge(['Find the DES (56-bit) row. That\'s why DES was retired in lesson 02.', 'Find the AES-256 row. Compare it with the age of the universe.']); ?>
        </div>
    <?php endif; ?>
    <?php remember('longer keys defeat brute force. Never build keys from short PINs or simple passwords.'); ?>
<?php step_end(); ?>

<?php step_start(2, 'Side channel: stealing a secret with a stopwatch', 'timing',
    'A server checks a secret token one character at a time and stops at the <b>first wrong character</b>. So a guess with more correct characters takes slightly <b>longer</b> to be rejected. The attacker never breaks any math. They just measure time.'); ?>
    <?php todo(['Press the button. The attacker guesses the hidden token one character at a time, using <b>only</b> timing.', 'Compare the "slowest guess" column with the "typical wrong guess" column.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="timing">
        <div class="inline">
            <div><label>Secret token length</label>
                <select name="length"><?php foreach ([2, 3, 4, 5] as $l): ?><option <?= (int) post('length', '4') === $l ? 'selected' : '' ?>><?= $l ?></option><?php endforeach; ?></select>
            </div>
            <button>Attack using timing only</button>
        </div>
    </form>
    <?php if (isset($out['timing'])): $t = $out['timing']; ?>
        <div class="output">
            <table>
                <tr><th>Character #</th><th>Slowest guess (= chosen)</th><th>Its time</th><th>Typical wrong guess</th></tr>
                <?php foreach ($t['attack']['log'] as $l): ?>
                    <tr><td><?= $l['position'] ?></td><td><code><?= h($l['chosen']) ?></code></td><td><?= $l['slowest'] ?> ms</td><td><?= $l['median'] ?> ms</td></tr>
                <?php endforeach; ?>
            </table>
            <?php row('The real secret token', $t['secret']); ?>
            <?php row('What the attacker recovered', $t['attack']['recovered'] . ($t['attack']['success'] ? '  (exact match!)' : '  (a busy computer added noise; just run it again)'), $t['attack']['success'] ? 'bad' : ''); ?>
            <?php explain('For each position, the correct character was the one that made the server "think" a little longer. In real life the difference is billionths of a second. We exaggerated it to ' . (SideChannel::DELAY_US / 1000) . ' ms so you can see it, but attackers do measure tiny differences over thousands of tries.'); ?>
            <h3>The fix: compare in constant time</h3>
            <?php row('Safe check, wrong first character', number_format($t['safeWrong'], 4) . ' ms'); ?>
            <?php row('Safe check, right first character', number_format($t['safeRight'], 4) . ' ms', 'good'); ?>
            <p class="explain">PHP's <code>hash_equals()</code> always takes the same time, so there's nothing to measure. Other side channels include power use, sound, electromagnetic signals and overly detailed error messages.</p>
        </div>
    <?php endif; ?>
    <?php remember('side-channel attacks target the implementation, not the algorithm.'); ?>
<?php step_end(); ?>

<?php step_start(3, 'Cryptanalysis A: patterns leaking through ECB mode', 'ecb',
    'Cryptanalysis means finding weaknesses that are cheaper than brute force. One classic mistake is using AES in "ECB mode", where identical 16-character chunks always produce identical encrypted chunks.'); ?>
    <?php todo(['Press the button with the example text: it repeats "ATTACK AT DAWN!!" (exactly 16 characters).', 'Compare the yellow (repeated) blocks in the ECB and CBC columns.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="ecb">
        <label>Message (repeat a 16-character chunk to see the effect)</label>
        <textarea name="ecbtext"><?= h(post('ecbtext', 'ATTACK AT DAWN!!ATTACK AT DAWN!!RETREAT AT DUSK!ATTACK AT DAWN!!')) ?></textarea>
        <button>Encrypt with ECB and CBC</button>
    </form>
    <?php if (isset($out['ecb'])): $e = $out['ecb']; ?>
        <div class="output">
            <div class="grid">
                <div class="mini"><h3>Your message in 16-char blocks</h3><?= blockList($e['plainBlocks'], Cryptanalysis::repeatedBlocks($e['plainBlocks'])) ?></div>
                <div class="mini"><h3>AES-ECB: repeats visible (bad)</h3><?= blockList($e['ecbBlocks'], Cryptanalysis::repeatedBlocks($e['ecbBlocks'])) ?></div>
                <div class="mini"><h3>AES-CBC: no repeats (good)</h3><?= blockList($e['cbcBlocks'], Cryptanalysis::repeatedBlocks($e['cbcBlocks'])) ?></div>
            </div>
            <?php explain('In ECB, the repeated "ATTACK AT DAWN!!" blocks produce the <b>same</b> ciphertext, so an analyst learns "this order was given three times" without any key. CBC (and the GCM mode used everywhere else in this lab) mixes in a random IV and the previous block, so the patterns disappear.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('a strong algorithm used the wrong way can still leak information.'); ?>
<?php step_end(); ?>

<?php step_start(4, 'Cryptanalysis B: making hashes collide (birthday attack)', 'birthday',
    'In a class of just 23 students, there\'s a 50% chance two share a birthday. The same "birthday trick" makes hash collisions much easier to find than you\'d expect. We compare only the first few bits of each hash so it finishes quickly.'); ?>
    <?php todo(['Keep MD5 and 24 bits, press the button.', 'Try 28 and 32 bits. How many more tries does it take?']); ?>
    <form method="post">
        <input type="hidden" name="action" value="birthday">
        <div class="inline">
            <div><label>Hash</label><select name="algo"><option value="md5">MD5</option><option value="sha256" <?= post('algo') === 'sha256' ? 'selected' : '' ?>>SHA-256</option></select></div>
            <div><label>Bits compared</label><select name="bits"><?php foreach ([16, 20, 24, 28, 32] as $bt): ?><option <?= (int) post('bits', '24') === $bt ? 'selected' : '' ?>><?= $bt ?></option><?php endforeach; ?></select></div>
            <button>Find a collision</button>
        </div>
    </form>
    <?php if (isset($out['birthday'])): $c = $out['birthday']; ?>
        <div class="output">
            <?php if ($c['found']): ?>
                <?php row('Input A', $c['inputA']); ?>
                <?php row('Input B', $c['inputB']); ?>
                <?php row('Hash A', $c['hashA']); ?>
                <?php row('Hash B', $c['hashB']); ?>
                <?php row('They start the same', $c['prefix'], 'bad'); ?>
                <?php row('Tries needed', number_format($c['tries']) . ' (expected ≈ ' . number_format($c['expected']) . ', instead of ' . number_format($c['brute']) . ' for brute force) in ' . round($c['ms']) . ' ms'); ?>
                <?php explain('Two different inputs produced the same first bits after only about the <b>square root</b> of the possibilities. That\'s why hashes must be long. MD5 has a worse problem on top: mathematical flaws let researchers create <b>full</b> 128-bit MD5 collisions in seconds. That\'s why MD5 is called broken. SHA-256, with 256 bits, would need about 2<sup>128</sup> tries, which is out of reach.'); ?>
            <?php else: ?>
                <?php notice('No collision within the limit. Try fewer bits.', 'warn'); ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    <?php remember('short or flawed hashes collide. Use SHA-256 or better.'); ?>
<?php step_end(); ?>

<?php step_start(5, 'Backdoors: when "secure" isn\'t', 'backdoor',
    'This "secure messenger" really does use AES-256. But it secretly attaches a copy of every message key, encrypted for a hidden third party. Looking at the output, the user can\'t tell anything is wrong.'); ?>
    <?php todo(['Type a private message and press <b>Send</b>.', 'Look at the last row. Who else could read it?']); ?>
    <form method="post">
        <input type="hidden" name="action" value="backdoor">
        <label>Private message</label>
        <input type="text" name="privmsg" value="<?= h(post('privmsg', 'Meeting with the journalist at 7pm')) ?>">
        <button>Send with the "secure" messenger</button>
    </form>
    <?php if (isset($out['backdoor'])): $d = $out['backdoor']; ?>
        <div class="output">
            <?php row('Ciphertext (looks perfectly secure)', $d['packet']['ciphertext'], 'bad'); ?>
            <?php row('An innocent-looking "metadata" field', shorten($d['packet']['metadata'], 80)); ?>
            <?php row('Recipient decrypts (expected)', $d['user'], 'good'); ?>
            <?php row('Hidden third party decrypts too', $d['agency'], 'bad'); ?>
            <?php explain('The "metadata" was actually the message key, encrypted with the third party\'s public key, so they can read <b>every</b> message without ever being given the key. Governments have been accused of pushing for weakened standards and hidden backdoors. Defence: prefer <b>open, publicly reviewed</b> algorithms and software that experts worldwide can inspect.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('strong math doesn\'t help if the software is designed to betray you.'); ?>
<?php step_end(); ?>

<?php check_yourself([
    ['What makes a brute-force attack impractical?', ['A long key (huge key space)', 'A short PIN', 'Using MD5'], 0,
        'Each extra bit doubles the work. 2<sup>256</sup> keys can\'t all be tried.'],
    ['A side-channel attack works by…', ['Breaking the AES math', 'Measuring indirect effects like timing or power use', 'Guessing passwords'], 1,
        'It attacks how the system behaves, not the cipher itself.'],
    ['Why is ECB mode dangerous?', ['It is slow', 'Identical plaintext blocks give identical ciphertext blocks, revealing patterns', 'It needs two keys'], 1,
        'Use modes with a random IV, like CBC or GCM.'],
    ['What is the best protection against hidden backdoors?', ['Secret, closed algorithms', 'Open algorithms and software reviewed publicly by experts', 'Shorter keys'], 1,
        'Public review makes hidden weaknesses much harder to slip in.'],
]); ?>

<section class="card">
    <h2>You finished the lab!</h2>
    <p>You've encrypted, decrypted, signed, hashed, shared keys, protected databases and web forms, and attacked weak setups. From lesson 01 to 07, the big ideas:</p>
    <ul>
        <li><b>Symmetric</b> (AES) is fast; <b>asymmetric</b> (RSA, ECC) solves key sharing. Real systems combine both.</li>
        <li><b>Hashes</b> are one-way fingerprints for integrity and passwords.</li>
        <li>Security depends on <b>key length</b>, <b>correct use</b> and <b>key management</b> as much as on the algorithm.</li>
    </ul>
</section>

<?php page_footer(); ?>
