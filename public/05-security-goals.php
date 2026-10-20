<?php
/**
 * Lesson 05 — What encryption protects
 *   Confidentiality, Integrity, Authentication, Nonrepudiation, Availability
 * Reuses code from EncryptionEngine, Hashing and AsymmetricCiphers.
 */

require __DIR__ . '/../src/bootstrap.php';

$message = post('message', 'Pay Juan Dela Cruz ₱10,000');
$out     = [];
$error   = null;

// Keys for this page. The HMAC key is a SHARED secret; Alice's RSA key pair is personal.
$secretKey  = $keyManager->getOrCreate('lesson05-aes');
$sharedHmac = $keyManager->getOrCreate('lesson05-hmac-shared');
if ($keyManager->loadPem('alice-private') === null) {
    $pair = AsymmetricCiphers::rsaGenerateKeyPair(2048);
    $keyManager->savePem('alice-private', $pair['private']);
    $keyManager->savePem('alice-public', $pair['public']);
}
$alicePrivate = $keyManager->loadPem('alice-private');
$alicePublic  = $keyManager->loadPem('alice-public');

try {
    switch (action()) {
        case 'confidentiality':
            $out['conf'] = EncryptionEngine::encrypt($message, $secretKey);
            break;

        case 'integrity':
            // Sender sends message + its hash. An attacker may change the message in transit.
            $sentHash     = hash('sha256', $message);
            $tampered     = post('tamper') === '1';
            $received     = $tampered ? str_replace('10,000', '90,000', $message) . '!' : $message;
            $out['integ'] = ['sentHash' => $sentHash, 'received' => $received, 'receivedHash' => hash('sha256', $received),
                             'ok' => Hashing::verifyIntegrity($received, $sentHash), 'tampered' => $tampered];
            // AES-GCM has integrity built in: flip one bit of the ciphertext and decryption refuses.
            $pkg = base64_decode(EncryptionEngine::encrypt($message, $secretKey));
            $pkg[strlen($pkg) - 1] = chr(ord($pkg[strlen($pkg) - 1]) ^ 1);
            try {
                EncryptionEngine::decrypt(base64_encode($pkg), $secretKey);
                $out['gcm'] = 'Decrypted (should not happen!)';
            } catch (RuntimeException $e) {
                $out['gcm'] = $e->getMessage();
            }
            break;

        case 'authentication':
            $forgedMsg   = $message . ' and ₱50,000 more';
            $realTag     = Hashing::hmac($message, $sharedHmac);
            $forgedTag   = Hashing::hmac($forgedMsg, random_bytes(32)); // the attacker doesn't have the key
            $out['auth'] = [
                'realTag'   => $realTag,
                'realOk'    => hash_equals(Hashing::hmac($message, $sharedHmac), $realTag),
                'forgedMsg' => $forgedMsg,
                'forgedTag' => $forgedTag,
                'forgedOk'  => hash_equals(Hashing::hmac($forgedMsg, $sharedHmac), $forgedTag),
            ];
            break;

        case 'nonrepudiation':
            $out['sig']   = AsymmetricCiphers::sign($message, $alicePrivate);
            $out['sigOk'] = AsymmetricCiphers::verify($message, $out['sig'], $alicePublic);
            break;

        case 'availability-backup':
            $keyManager->save('lesson05-backup', $secretKey);
            $out['avail'] = true;
            break;

        case 'availability-lose':
            $ciphertext = EncryptionEngine::encrypt($message, $secretKey);
            $keyManager->delete('lesson05-aes');                       // key lost
            try {
                $newKey = $keyManager->getOrCreate('lesson05-aes');     // the app makes a new one…
                EncryptionEngine::decrypt($ciphertext, $newKey);        // …which can't open old data
            } catch (RuntimeException) {
                $out['lost'] = true;
            }
            if ($keyManager->has('lesson05-backup')) {
                $restored = $keyManager->load('lesson05-backup');
                $keyManager->save('lesson05-aes', $restored);
                $out['restored'] = EncryptionEngine::decrypt($ciphertext, $restored);
            }
            $secretKey = $keyManager->load('lesson05-aes');
            break;
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

/** Small helper: every step posts the same message field plus its own action. */
function messageForm(string $action, string $button, string $message, string $extra = ''): void
{ ?>
    <form method="post">
        <input type="hidden" name="action" value="<?= h($action) ?>">
        <label>Message</label>
        <input type="text" name="message" value="<?= h($message) ?>">
        <?= $extra ?>
        <button><?= h($button) ?></button>
    </form>
<?php }

page_header('05 · What Encryption Protects', 'Encryption and hashing serve five security goals. Here\'s one hands-on demo for each.');

lesson_intro(
    [
        '<b>Confidentiality</b>: keep data secret',
        '<b>Integrity</b>: detect if data was changed',
        '<b>Authentication</b>: confirm where data came from',
        '<b>Nonrepudiation</b>: make it impossible for a sender to deny sending',
        '<b>Availability</b>: make sure the rightful owner can still get to the data',
    ],
    [
        'HMAC'      => 'A hash mixed with a secret key. Only people who know the key can create a valid one.',
        'Tamper'    => 'To secretly change data, e.g. editing a payment amount in transit.',
        'Repudiate' => 'To deny something. "I never sent that message!"',
        'CIA triad' => 'Confidentiality, Integrity, Availability: the three classic goals of information security.',
    ]
);
?>

<?php if ($error): notice('Error: ' . h($error), 'error'); endif; ?>

<p class="explain">Scenario for this whole lesson: Alice sends her bank a payment order. Let's protect it in five different ways.</p>

<?php step_start(1, 'Confidentiality: only the right people can read it', 'confidentiality'); ?>
    <?php todo(['Press <b>Encrypt</b> and compare what an eavesdropper sees with what the key holder sees.']); ?>
    <?php messageForm('confidentiality', 'Encrypt', $message); ?>
    <?php if (isset($out['conf'])): ?>
        <div class="output">
            <?php row('What a hacker on the Wi-Fi sees', $out['conf'], 'bad'); ?>
            <?php row('What the bank (with the key) sees', EncryptionEngine::decrypt($out['conf'], $secretKey), 'good'); ?>
            <?php explain('This is what you did in lessons 01–03. Without the key, nobody can learn who\'s being paid or how much. That prevents data leaks.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('confidentiality = encryption keeps data secret.'); ?>
<?php step_end(); ?>

<?php step_start(2, 'Integrity: detect any change', 'integrity'); ?>
    <?php todo([
        'Press <b>Send</b>: the message arrives with its hash, and they match.',
        'Tick <b>"A hacker changes the amount"</b> and press <b>Send</b> again.',
    ]); ?>
    <?php messageForm('integrity', 'Send message + its hash', $message,
        '<div class="checks"><label><input type="checkbox" name="tamper" value="1" ' . (post('tamper') === '1' ? 'checked' : '') . '> A hacker changes the amount on the way</label></div>'); ?>
    <?php if (isset($out['integ'])): $i = $out['integ']; ?>
        <div class="output">
            <?php row('Hash sent along with the message', $i['sentHash']); ?>
            <?php row('Message that arrived', $i['received']); ?>
            <?php row('Hash of what arrived', $i['receivedHash']); ?>
            <?php row('Integrity check', $i['ok'] ? 'Unchanged' : 'CHANGED — the bank rejects it', $i['ok'] ? 'good' : 'bad'); ?>
            <?php row('Bonus: AES-GCM ciphertext with 1 bit flipped', $out['gcm'], 'bad'); ?>
            <?php explain($i['tampered']
                ? 'The hacker changed the amount, so the hash of what arrived no longer matches the hash that was sent. Tampering detected! The last row shows that AES-GCM (the encryption used in this lab) also has a built-in tamper seal: flipping a single bit makes decryption refuse.'
                : 'The hashes match, so the message arrived exactly as sent. Now tick the box to see what tampering looks like.'); ?>
            <?php hint('A clever hacker could change the message <i>and</i> replace the hash with a new one. That\'s why the next step adds a secret key to the hash.', 'Wait, can\'t the hacker just send a new hash too?'); ?>
        </div>
    <?php endif; ?>
    <?php remember('integrity = a hash (or a tamper seal) reveals any change.'); ?>
<?php step_end(); ?>

<?php step_start(3, 'Authentication: confirm who it came from', 'authentication',
    'Alice and her bank share a secret key. Alice attaches an <b>HMAC</b>, a hash made with that secret. A hacker without the key can\'t make a valid one.'); ?>
    <?php todo(['Press the button. It checks Alice\'s genuine message and a hacker\'s forged one.']); ?>
    <?php messageForm('authentication', 'Check genuine vs. forged message', $message); ?>
    <?php if (isset($out['auth'])): $a = $out['auth']; ?>
        <div class="output">
            <h3>Alice's real message</h3>
            <?php row('HMAC tag', $a['realTag']); ?>
            <?php row('Bank\'s check', $a['realOk'] ? 'Authentic: made by someone with the shared key' : 'Rejected', $a['realOk'] ? 'good' : 'bad'); ?>
            <h3>Hacker's forged message</h3>
            <?php row('Message', $a['forgedMsg']); ?>
            <?php row('HMAC tag (made without the key)', $a['forgedTag']); ?>
            <?php row('Bank\'s check', $a['forgedOk'] ? 'Accepted (the forgery got through)' : 'Rejected: not made by a key holder', $a['forgedOk'] ? 'bad' : 'good'); ?>
            <?php explain('The hacker could change the text and compute a new tag, but without the secret key that tag doesn\'t match what the bank calculates. So the bank knows the real message came from someone who has the key.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('authentication = proof that data came from someone who holds the right key.'); ?>
<?php step_end(); ?>

<?php step_start(4, 'Nonrepudiation: the sender can\'t deny it', 'nonrepudiation',
    'With HMAC there\'s a catch: the bank <i>also</i> knows the key, so Alice could claim "the bank made that message, not me!". A <b>digital signature</b> fixes this because only Alice has her private key.'); ?>
    <?php todo(['Press the button to have Alice sign the payment order.']); ?>
    <?php messageForm('nonrepudiation', 'Alice signs the order', $message); ?>
    <?php if (isset($out['sig'])): ?>
        <div class="output">
            <?php row('Alice\'s digital signature', $out['sig']); ?>
            <?php row('Anyone checks it with Alice\'s public key', $out['sigOk'] ? 'Valid: only Alice could have signed this' : 'Invalid', $out['sigOk'] ? 'good' : 'bad'); ?>
            <?php explain('The signature could only be made with Alice\'s <b>private</b> key, which nobody else has, not even the bank. So Alice can\'t later deny sending the order. HMAC can\'t give this guarantee because the key is shared.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('nonrepudiation = digital signatures, because only one person holds the private key.'); ?>
<?php step_end(); ?>

<?php step_start(5, 'Availability: don\'t lock yourself out', 'availability',
    'Encryption can also <b>hurt</b> availability. If the key is lost, even the owner can\'t read their own data. Good key management means backups.'); ?>
    <?php todo([
        'First press <b>Simulate losing the key</b> <i>without</i> a backup and see what happens.',
        'Then press <b>Back up the key</b>, and simulate losing it again.',
    ]); ?>
    <form method="post">
        <input type="hidden" name="message" value="<?= h($message) ?>">
        <button name="action" value="availability-lose" class="danger">Simulate losing the key</button>
        <button name="action" value="availability-backup" class="secondary">Back up the key</button>
    </form>
    <?php if (isset($out['avail'])): notice('Key backed up to <code>' . h(storage_path('keys/lesson05-backup.key')) . '</code>. Now simulate losing the key.', 'success'); endif; ?>
    <?php if (isset($out['lost'])): ?>
        <div class="output">
            <?php notice('The key is gone. The encrypted data can\'t be opened, not even by its owner.', 'error'); ?>
            <?php if (isset($out['restored'])): ?>
                <?php row('Restored from the backup', $out['restored'], 'good'); ?>
                <?php explain('Because a backup of the key existed, the data was recovered. The data stayed <b>available</b> to its rightful owner.'); ?>
            <?php else: ?>
                <?php explain('No backup existed, so the data is lost forever. Ransomware works on exactly this idea: criminals encrypt your files and keep the key. Now press <b>Back up the key</b> and try again.'); ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    <?php remember('availability = authorised people can still reach the data. Back up your keys!'); ?>
<?php step_end(); ?>

<?php check_yourself([
    ['A hacker reads your bank messages on public Wi-Fi. Which goal failed?', ['Confidentiality', 'Availability', 'Nonrepudiation'], 0,
        'Confidentiality means only authorised people can read the data.'],
    ['Which tool detects that a message was changed in transit?', ['A hash / tamper seal', 'A longer password', 'Deleting the key'], 0,
        'Any change produces a different hash.'],
    ['Why does a digital signature give nonrepudiation but HMAC does not?', ['HMAC is slower', 'With HMAC both sides share the key; a signature uses a private key only the sender has', 'Signatures are encrypted'], 1,
        'A shared key means either side could have produced the HMAC.'],
    ['You lose your only encryption key. Which goal suffers?', ['Integrity', 'Availability', 'Authentication'], 1,
        'Without the key, even you can\'t get to your data.'],
]); ?>

<?php page_footer(); ?>
