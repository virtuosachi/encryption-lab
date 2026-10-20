<?php
/**
 * Lesson 01 — Encryption basics
 * Code used:  src/KeyManager.php  and  src/EncryptionEngine.php
 *
 * Page pattern used in EVERY lesson:
 *   1. PHP at the top handles the form that was submitted (the "controller").
 *   2. HTML at the bottom shows the guided steps, forms and results (the "view").
 * JS analogy: like an Express route handler that then renders a template.
 */

require __DIR__ . '/../src/bootstrap.php';

$plaintext = post('plaintext', 'Meet me at the library at 3pm.');
$result    = [];     // output for the template
$error     = null;

try {
    switch (action()) {                      // which button was pressed?
        case 'encrypt':
            $key     = $keyManager->getOrCreate('lesson01');
            $package = EncryptionEngine::encrypt($plaintext, $key);
            $raw     = base64_decode($package);
            $result = [
                'key'        => $key,
                'package'    => $package,
                'iv'         => substr($raw, 0, 12),
                'tag'        => substr($raw, 12, 16),
                'ciphertext' => substr($raw, 28),
            ];
            break;

        case 'compare':
            // Same message encrypted three ways, to show the output is always different.
            $key    = $keyManager->getOrCreate('lesson01');
            $result = ['compare' => [
                'First time (lesson key)'         => EncryptionEngine::encrypt($plaintext, $key),
                'Second time (same lesson key)'   => EncryptionEngine::encrypt($plaintext, $key),
                'With a completely different key' => EncryptionEngine::encrypt($plaintext, KeyManager::generateKey()),
            ]];
            break;

        case 'decrypt':
            $result = ['manual' => EncryptionEngine::decrypt(post('package'), $keyManager->getOrCreate('lesson01')), 'how' => 'right'];
            break;

        case 'decrypt-wrong-key':
            // A fresh random key is NOT the key that encrypted the data -> must fail.
            $result = ['how' => 'wrong'];
            $result['manual'] = EncryptionEngine::decrypt(post('package'), KeyManager::generateKey());
            break;

        case 'rotate':
            $keyManager->delete('lesson01');
            $keyManager->getOrCreate('lesson01');
            $result = ['rotated' => true];
            break;
    }
} catch (Throwable $e) {                      // Throwable catches every error type (like catch (e) in JS)
    $error = $e->getMessage();
}

$currentKey = $keyManager->getOrCreate('lesson01');

page_header('01 · Encryption Basics', 'Turn a readable message into secret code, then turn it back.');

lesson_intro(
    [
        'encrypt your first message and look inside the result',
        'see why the same message never encrypts the same way twice',
        'decrypt it, and find out what happens with the wrong key',
        'meet the three parts every encryption system has',
    ],
    [
        'Plaintext'  => 'The normal, readable data. Example: <code>Hello</code>.',
        'Ciphertext' => 'The scrambled, unreadable version. Example: <code>x9$Lq#2v…</code>',
        'Key'        => 'The secret value that locks and unlocks the data. Without it, ciphertext is useless.',
        'Algorithm (cipher)' => 'The recipe used to scramble the data. This lesson uses <b>AES</b>, the most widely used one.',
    ]
);
?>

<?php if ($error): notice('Error: ' . h($error), 'error'); endif; ?>

<?php step_start(1, 'Meet the three parts of an encryption system', 'parts',
    'Before pressing any buttons, here are the three parts working behind this page. You\'ll see them in every lesson.'); ?>
    <div class="grid">
        <div class="mini"><h3>1 · Data</h3>Whatever you want to protect: the message you'll type in step 2.</div>
        <div class="mini"><h3>2 · Encryption engine</h3>The machine that scrambles and unscrambles. Here it's AES-256.</div>
        <div class="mini"><h3>3 · Key manager</h3>Creates the keys and keeps them safe, away from the data.</div>
    </div>
    <p>Why keep them apart? If a thief steals the data but not the key, they get nothing useful. Big companies run each part on <b>different servers</b> for this reason. On a single laptop, like this lab, all three simply run on the same machine.</p>
    <?php remember('data + engine + key manager. Lose the key and the data is just noise.'); ?>
    <?php code_ref('src/EncryptionEngine.php, src/KeyManager.php', 'one class for each part.'); ?>
<?php step_end(); ?>

<?php step_start(2, 'Encrypt your first message', 'encrypt'); ?>
    <?php todo([
        'Type any message in the box (or keep the example).',
        'Press <b>Encrypt</b>.',
        'Look at the red <b>ciphertext</b> that appears. Can you read anything?',
    ]); ?>
    <form method="post">
        <input type="hidden" name="action" value="encrypt">
        <label for="plaintext">Your message (plaintext)</label>
        <textarea id="plaintext" name="plaintext"><?= h($plaintext) ?></textarea>
        <button>Encrypt</button>
    </form>

    <?php if (isset($result['package'])): ?>
        <div class="output">
            <div class="flow">
                <span class="box plain">Plaintext</span><span class="arrow">→</span>
                <span class="box">AES-256 + key</span><span class="arrow">→</span>
                <span class="box cipher">Ciphertext</span>
            </div>
            <?php
            row('Your message', $plaintext, 'good');
            row('Encrypted result', $result['package'], 'bad');
            ?>
            <details class="hint"><summary>Look inside the encrypted result</summary><div>
                <?php
                row('Algorithm used', EncryptionEngine::CIPHER);
                row('Key (64 hex characters = 256 bits)', hex($result['key']));
                row('IV — a random "starter" value', hex($result['iv']));
                row('Tag — a tamper seal', hex($result['tag']));
                row('The scrambled bytes', hex($result['ciphertext']));
                ?>
                <p class="explain">The result bundles three things: the IV, the tamper seal and the scrambled message. Only the scrambled part is secret. The IV and tag are safe to send along with it.</p>
            </div></details>
            <?php explain('Three things went into the encryption: your <b>message</b>, the <b>algorithm</b> (AES-256), and a <b>secret key</b> (256 random bits). The algorithm mixed the message and key together into ciphertext. Nothing in it reveals your message, but it\'s about the same length, plus a few extra bytes for the IV and tag.'); ?>
            <?php challenge([
                'Encrypt a single letter, then a whole paragraph. How does the ciphertext length change?',
                'Copy the encrypted result. You\'ll need it in step 4.',
            ]); ?>
        </div>
    <?php endif; ?>
    <?php code_ref('src/EncryptionEngine.php', 'the <code>encrypt()</code> function.'); ?>
<?php step_end(); ?>

<?php step_start(3, 'Same message, different result every time', 'compare',
    'Here\'s something surprising: encrypting the same message twice gives two different results.'); ?>
    <?php todo(['Press the button. It encrypts your message three times.', 'Compare the three red results.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="compare">
        <input type="hidden" name="plaintext" value="<?= h($plaintext) ?>">
        <button>Encrypt "<?= h(shorten($plaintext, 30)) ?>" three times</button>
    </form>
    <?php if (isset($result['compare'])): ?>
        <div class="output">
            <?php foreach ($result['compare'] as $label => $c): row($label, $c, 'bad'); endforeach; ?>
            <?php explain('All three are different. With the <b>same key</b>, a fresh random IV is mixed in each time, so the output changes. With a <b>different key</b>, the output changes completely. That way an eavesdropper can\'t even tell that two messages say the same thing (for example, "yes" sent twice).'); ?>
        </div>
    <?php endif; ?>
    <?php remember('a random key and a random IV make every ciphertext unique.'); ?>
<?php step_end(); ?>

<?php step_start(4, 'Decrypt it, and try the wrong key', 'decrypt'); ?>
    <?php todo([
        'Paste the encrypted result from step 2 (it\'s filled in automatically if you just did step 2).',
        'Press <b>Decrypt with the right key</b>. You should get your message back.',
        'Now press <b>Decrypt with a wrong key</b>. What happens?',
    ]); ?>
    <form method="post">
        <label for="package">Encrypted result</label>
        <textarea id="package" name="package" data-sync="package" placeholder="Paste the encrypted result from step 2"><?= h(post('package', $result['package'] ?? '')) ?></textarea>
        <button name="action" value="decrypt">Decrypt with the right key</button>
        <button name="action" value="decrypt-wrong-key" class="secondary">Decrypt with a wrong key</button>
    </form>
    <?php if (isset($result['manual'])): ?>
        <div class="output">
            <?php row('Recovered message', $result['manual'], 'good'); ?>
            <?php explain('The same key that locked the data unlocked it, and you got your exact original message back.'); ?>
        </div>
    <?php elseif (($result['how'] ?? '') === 'wrong' && $error): ?>
        <?php explain('Decryption <b>refused</b> to work. With the wrong key you don\'t even get garbage. AES-GCM notices that the key doesn\'t match the tamper seal and stops. Without the right key, the data is useless.'); ?>
    <?php endif; ?>
    <?php hint('If you see "not a valid ciphertext package", the text box is empty or the text was cut off. Go back to step 2, encrypt again, and copy the whole red value.'); ?>
<?php step_end(); ?>

<?php step_start(5, 'The key manager: replacing a key', 'keys',
    'Organisations change ("rotate") their keys regularly. Let\'s see what that means for old data.'); ?>
    <?php row('Current lesson key', hex($currentKey)); ?>
    <?php row('Saved in the file', storage_path('keys/lesson01.key')); ?>
    <?php todo([
        'Encrypt a message in step 2 and copy the result.',
        'Press <b>Replace the key</b> below.',
        'Go back to step 4 and try to decrypt the old result with the "right" key.',
    ]); ?>
    <form method="post">
        <input type="hidden" name="action" value="rotate">
        <button class="danger">Replace the key (delete it and make a new one)</button>
    </form>
    <?php if (isset($result['rotated'])): ?>
        <?php notice('A new key was created. The key value above has changed.', 'warn'); ?>
        <?php explain('Data locked with the <b>old</b> key can no longer be opened, because that key is gone. In real systems, before throwing an old key away, you first decrypt the data and re-encrypt it with the new key.'); ?>
    <?php endif; ?>
    <?php remember('protecting and backing up keys matters as much as the encryption itself.'); ?>
    <?php code_ref('src/KeyManager.php', '<code>generateKey()</code>, <code>save()</code>, <code>delete()</code>.'); ?>
<?php step_end(); ?>

<?php check_yourself([
    ['What is <i>ciphertext</i>?', ['The readable original message', 'The scrambled, unreadable version of the message', 'The secret key'], 1,
        'Plaintext goes in, ciphertext comes out.'],
    ['You encrypt "yes" twice with the same key. The two results are…', ['Identical', 'Different, because a random IV is used each time', 'Impossible to compute'], 1,
        'The random IV makes every encryption unique, so attackers can\'t spot repeated messages.'],
    ['What happens if you try to decrypt with the wrong key?', ['You get the message anyway', 'You get part of the message', 'Decryption fails: no readable message'], 2,
        'Without the right key, the data stays locked.'],
    ['Which part creates and stores the keys?', ['The data', 'The encryption engine', 'The key manager'], 2,
        'The key manager handles keys, and ideally runs separately from the data.'],
]); ?>

<?php page_footer(); ?>
