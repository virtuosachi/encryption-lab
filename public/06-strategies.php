<?php
/**
 * Lesson 06 — Encryption in the real world (implementation strategies)
 * Code used: src/Strategies.php
 */

require __DIR__ . '/../src/bootstrap.php';

$out   = [];
$error = null;

$cloud = new CloudStorage($keyManager);
$e2ee  = new E2eeDemo($keyManager);
$field = new FieldLevel($keyManager);
try {
    $db = new ColumnEncryptedDb($keyManager);
} catch (Throwable $e) {
    $db    = null;
    $error = $e->getMessage();
}

try {
    switch (action()) {
        /* 1. BYOE */
        case 'byoe':
            $record          = ByoeDemo::customerEncrypts(post('passphrase'), post('data'));
            $out['byoe']     = $record;
            $out['byoeBack'] = ByoeDemo::decryptWith(post('passphrase'), $record);
            try {
                ByoeDemo::decryptWith('provider-guess', $record);
                $out['byoeProvider'] = 'Provider could read it (bad)';
            } catch (RuntimeException) {
                $out['byoeProvider'] = 'Can\'t decrypt: it never had your key';
            }
            break;

        /* 2. Cloud storage */
        case 'cloud-upload':
            $out['uploaded'] = $cloud->upload(post('filename', 'notes.txt'), post('content'));
            break;
        case 'cloud-open':
            $out['opened'] = ['name' => post('file'), 'raw' => $cloud->rawContents(post('file')), 'plain' => $cloud->download(post('file'))];
            break;
        case 'cloud-delete':
            $cloud->delete(post('file'));
            break;

        /* 3. Column-level */
        case 'db-insert':
            $db?->insert(post('name'), post('department'), post('salary')); // ?-> = optional chaining (JS: db?.insert)
            $out['inserted'] = true;
            break;
        case 'db-clear':
            $db?->clear();
            break;

        /* 4. E2EE */
        case 'e2ee':
            $packet      = $e2ee->send('alice', 'bob', post('chat'));
            $out['e2ee'] = [
                'packet'  => $packet,
                'bob'     => $e2ee->receive('bob', 'alice', $packet),
                'server'  => $e2ee->receive('server', 'alice', $packet), // the server tries with ITS keys
                'alicePk' => hex($e2ee->publicKey('alice')),
                'bobPk'   => hex($e2ee->publicKey('bob')),
            ];
            break;

        /* 5. Field-level */
        case 'field':
            $form = [
                'full_name'   => post('full_name'),
                'email'       => post('email'),
                'card_number' => post('card_number'),
                'ssn'         => post('ssn'),
                'salary'      => post('salary'),
            ];
            $out['fieldStored']   = $field->protect($form);
            $out['fieldRevealed'] = $field->reveal($out['fieldStored']);
            break;

        /* 6. HTTPS */
        case 'https':
            $server      = HttpsDemo::createSelfSignedCertificate(post('domain', 'localhost'));
            $out['cert'] = $server;
            $out['tls']  = HttpsDemo::simulateHandshake('POST /login HTTP/1.1  user=ana&password=CorrectHorse42', $server);
            break;

        /* 7. Link-level */
        case 'link':
            $out['link'] = LinkLevel::send(post('linkmsg'));
            break;

        /* 8. Network-level */
        case 'network':
            $tunnelKey  = $keyManager->getOrCreate('ipsec-tunnel');
            $inner      = ['src' => '10.0.1.25', 'dst' => '10.0.2.40', 'protocol' => 'TCP', 'port' => 443, 'data' => post('netmsg')];
            $esp        = NetworkLevel::encapsulate($inner, $tunnelKey, '203.0.113.10', '198.51.100.20', 1001);
            $out['net'] = ['inner' => $inner, 'esp' => $esp, 'back' => NetworkLevel::decapsulate($esp, $tunnelKey)];
            // A router that rewrites the outer header -> authentication fails.
            $tampered = $esp;
            $tampered['header']['dst'] = '6.6.6.6';
            try {
                NetworkLevel::decapsulate($tampered, $tunnelKey);
                $out['netTamper'] = 'Accepted (bad)';
            } catch (RuntimeException) {
                $out['netTamper'] = 'Rejected — the header was changed in transit';
            }
            break;
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

page_header('06 · Encryption in the Real World', 'Eight ways organisations actually deploy encryption. Each step is a mini-simulation you can run.');

lesson_intro(
    [
        'compare who holds the key: <b>you</b> (BYOE) or the <b>provider</b> (cloud storage)',
        'encrypt just one <b>column</b> of a database, or just some <b>fields</b> of a form',
        'see why <b>end-to-end</b> encryption keeps even the chat server in the dark',
        'create an <b>HTTPS</b> certificate and follow a secure connection being set up',
        'follow a message through <b>link-level</b> and <b>network-level</b> (VPN) encryption',
    ],
    [
        'Cloud provider' => 'A company that stores or runs things for you online (Google Drive, AWS, Azure…).',
        'Database column'=> 'One "field" across all rows of a table, e.g. the salary of every employee.',
        'Certificate'    => 'A website\'s ID card: its public key plus its name, signed by a trusted authority.',
        'Router / hop'   => 'A device that passes data along on its way across a network.',
    ]
);
?>

<?php if ($error): notice('Error: ' . h($error), 'error'); endif; ?>

<!-- 1 ------------------------------------------------------------------ -->
<?php step_start(1, 'Bring Your Own Encryption (BYOE / BYOK)', 'byoe',
    'Your company stores data in the cloud but <b>keeps the key itself</b>. The cloud provider only ever sees scrambled data.'); ?>
    <?php todo(['Keep the example (or type your own key and data) and press the button.', 'Look at the "Cloud provider stores" rows: is there a key anywhere?']); ?>
    <form method="post">
        <input type="hidden" name="action" value="byoe">
        <div class="inline">
            <div><label>Your own secret key / passphrase</label><input type="text" name="passphrase" value="<?= h(post('passphrase', 'our-company-master-key-2026')) ?>"></div>
            <div><label>Business data to store in the cloud</label><input type="text" name="data" value="<?= h(post('data', 'Q3 merger plan: acquire XYZ Corp')) ?>"></div>
        </div>
        <button>Encrypt with my key, then upload</button>
    </form>
    <?php if (isset($out['byoe'])): ?>
        <div class="output">
            <?php row('Cloud provider stores: salt', $out['byoe']['salt']); ?>
            <?php row('Cloud provider stores: ciphertext', $out['byoe']['ciphertext'], 'bad'); ?>
            <?php row('Cloud provider tries to read it', $out['byoeProvider'], 'good'); ?>
            <?php row('Your company decrypts with its key', $out['byoeBack'], 'good'); ?>
            <?php explain('The data was encrypted <b>before</b> it left your company, using your own key. The provider stores it but can\'t read it, and neither can a hacker who breaks into the provider. The trade-off: if <i>you</i> lose the key, nobody can help you recover the data.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('BYOE = you keep the key, so the cloud only ever holds ciphertext.'); ?>
<?php step_end(); ?>

<!-- 2 ------------------------------------------------------------------ -->
<?php step_start(2, 'Cloud storage encryption', 'cloud',
    'Here the <b>cloud provider</b> manages the key and encrypts files automatically before writing them to disk. Our pretend cloud is the folder <code>storage/cloud/</code>.'); ?>
    <?php todo([
        'Press <b>Upload</b>.',
        'In the file list, press <b>Download</b> to compare the raw stored bytes with the decrypted content.',
        'Optional: open the <code>storage/cloud</code> folder on your computer and open the <code>.enc</code> file in a text editor.',
    ]); ?>
    <form method="post">
        <input type="hidden" name="action" value="cloud-upload">
        <label>File name</label>
        <input type="text" name="filename" value="<?= h(post('filename', 'customer-list.txt')) ?>">
        <label>File content</label>
        <textarea name="content"><?= h(post('content', "Ana Santos, 0917-123-4567\nBen Reyes, 0918-765-4321")) ?></textarea>
        <button>Upload (encrypted automatically)</button>
    </form>
    <?php if (isset($out['uploaded'])): notice('Uploaded <b>' . h($out['uploaded']) . '</b>. It\'s now in the list below.', 'success'); endif; ?>
    <?php $files = $cloud->files(); ?>
    <?php if ($files): ?>
        <h3>Files in your cloud</h3>
        <table>
            <?php foreach ($files as $f): ?>
                <tr><td><code><?= h($f) ?>.enc</code></td><td>
                    <form method="post" style="margin:0">
                        <input type="hidden" name="file" value="<?= h($f) ?>">
                        <button name="action" value="cloud-open" class="secondary" style="margin:0">Download</button>
                        <button name="action" value="cloud-delete" class="danger" style="margin:0">Delete</button>
                    </form>
                </td></tr>
            <?php endforeach; ?>
        </table>
    <?php endif; ?>
    <?php if (isset($out['opened'])): ?>
        <div class="output">
            <?php row('What is really on the cloud\'s disk', shorten($out['opened']['raw'], 200), 'bad'); ?>
            <?php row('What you get after downloading', $out['opened']['plain'], 'good'); ?>
            <?php explain('If someone steals the provider\'s hard drives, they only get scrambled bytes. But since the <b>provider</b> holds the key, you have to trust its key-management rules: who at the company can use the key, and when? That\'s the difference from BYOE in step 1.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('cloud storage encryption protects stolen disks, but the provider holds the key.'); ?>
<?php step_end(); ?>

<!-- 3 ------------------------------------------------------------------ -->
<?php step_start(3, 'Column-level encryption in a database', 'column',
    'In this real SQLite database, only the <b>salary</b> column is encrypted, and every salary uses the same column key. Names and departments stay readable so they can still be searched and sorted.'); ?>
    <?php if ($db): ?>
        <?php todo(['Add two or three employees with different salaries.', 'Compare the two tables: what the database file holds vs. what the payroll app shows.']); ?>
        <form method="post">
            <div class="inline">
                <div><label>Name</label><input type="text" name="name" value="<?= h(post('name', 'Maria Clara')) ?>"></div>
                <div><label>Department</label><input type="text" name="department" value="<?= h(post('department', 'Finance')) ?>"></div>
                <div><label>Salary</label><input type="text" name="salary" value="<?= h(post('salary', '48500')) ?>"></div>
            </div>
            <button name="action" value="db-insert">Add employee</button>
            <button name="action" value="db-clear" class="danger">Empty the table</button>
        </form>
        <?php $raw = $db->rawRows(); ?>
        <?php if ($raw): ?>
            <div class="output table-wrap">
                <h3>What's inside the database file (what a hacker or curious admin sees)</h3>
                <table>
                    <tr><th>id</th><th>name</th><th>department</th><th>salary_encrypted</th></tr>
                    <?php foreach ($raw as $r): ?>
                        <tr><td><?= h($r['id']) ?></td><td><?= h($r['name']) ?></td><td><?= h($r['department']) ?></td><td><code><?= h(shorten($r['salary_encrypted'], 50)) ?></code></td></tr>
                    <?php endforeach; ?>
                </table>
                <h3>What the authorised payroll app shows</h3>
                <table>
                    <tr><th>id</th><th>name</th><th>department</th><th>salary</th></tr>
                    <?php foreach ($db->decryptedRows() as $r): ?>
                        <tr><td><?= h($r['id']) ?></td><td><?= h($r['name']) ?></td><td><?= h($r['department']) ?></td><td><b><?= h($r['salary']) ?></b></td></tr>
                    <?php endforeach; ?>
                </table>
                <?php explain('Only the sensitive column is protected. Even a database administrator, or a hacker who steals the file, sees names but not salaries. The payroll app, which has the column key, sees everything.'); ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>
    <?php remember('column-level = encrypt one sensitive column, with one key for that whole column.'); ?>
<?php step_end(); ?>

<!-- 4 ------------------------------------------------------------------ -->
<?php step_start(4, 'End-to-end encryption (E2EE)', 'e2ee',
    'In WhatsApp, Signal and Messenger\'s encrypted chats, messages are encrypted on the <b>sender\'s phone</b> and decrypted only on the <b>recipient\'s phone</b>. The company\'s server in the middle just passes along data it can\'t read.'); ?>
    <div class="flow">
        <span class="box plain">Alice's phone<br>encrypts</span><span class="arrow">→</span>
        <span class="box cipher">Chat server<br>sees only gibberish</span><span class="arrow">→</span>
        <span class="box plain">Bob's phone<br>decrypts</span>
    </div>
    <?php todo(['Type a message from Alice to Bob and press <b>Send</b>.', 'Check what the server sees, and whether it can decrypt it.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="e2ee">
        <label>Alice's message to Bob</label>
        <input type="text" name="chat" value="<?= h(post('chat', 'Surprise party for Carla on Friday')) ?>">
        <button>Send</button>
    </form>
    <?php if (isset($out['e2ee'])): $e = $out['e2ee']; ?>
        <div class="output">
            <?php row("Alice's public key", $e['alicePk']); ?>
            <?php row("Bob's public key", $e['bobPk']); ?>
            <?php row('What the chat server relays', $e['packet'], 'bad'); ?>
            <?php row('Server tries to decrypt', $e['server'] === null ? 'Impossible: it has no matching private key' : $e['server'], 'good'); ?>
            <?php row("Bob's phone decrypts", (string) $e['bob'], 'good'); ?>
            <?php explain('Alice\'s phone encrypted the message with <b>Bob\'s public key</b> (lesson 03). Only <b>Bob\'s private key</b>, which never leaves his phone, can open it. Not the server, not the company, not a hacker who breaks into the server.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('E2EE = only the two ends can read the message, not even the service in between.'); ?>
<?php step_end(); ?>

<!-- 5 ------------------------------------------------------------------ -->
<?php step_start(5, 'Field-level encryption on a web form', 'field',
    'Some form fields are marked as sensitive. Anything typed in them is encrypted <b>automatically</b> before saving, and the other fields are stored normally.'); ?>
    <?php todo(['Fill in the form (fields marked "sensitive" are the protected ones) and press <b>Submit</b>.', 'Compare the "Stored in the database" column with the "Shown to staff" column.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="field">
        <div class="inline">
            <div><label>Full name</label><input type="text" name="full_name" value="<?= h(post('full_name', 'Jose Rizal')) ?>"></div>
            <div><label>Email</label><input type="text" name="email" value="<?= h(post('email', 'jose@example.com')) ?>"></div>
        </div>
        <div class="inline">
            <div><label>Credit card number (sensitive)</label><input type="text" name="card_number" value="<?= h(post('card_number', '4111 1111 1111 1111')) ?>"></div>
            <div><label>National ID / SSN (sensitive)</label><input type="text" name="ssn" value="<?= h(post('ssn', '123-45-6789')) ?>"></div>
            <div><label>Salary (sensitive)</label><input type="text" name="salary" value="<?= h(post('salary', '65000')) ?>"></div>
        </div>
        <button>Submit form</button>
    </form>
    <?php if (isset($out['fieldStored'])): ?>
        <div class="output table-wrap">
            <table>
                <tr><th>Field</th><th>Stored in the database</th><th>Shown to authorised staff</th></tr>
                <?php foreach ($out['fieldStored'] as $name => $stored): ?>
                    <tr>
                        <td><b><?= h($name) ?></b></td>
                        <td><code><?= h(shorten($stored, 48)) ?></code></td>
                        <td><?= h($name === 'card_number' ? FieldLevel::mask($out['fieldRevealed'][$name]) . '  (masked)' : $out['fieldRevealed'][$name]) ?></td>
                    </tr>
                <?php endforeach; ?>
            </table>
            <?php explain('Only the fields on the sensitive list (card number, ID, bank account, salary) were encrypted. Name and email stay plain so they can still be searched. Staff see the card number <b>masked</b>, showing only the last 4 digits, like on a receipt.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('field-level = pick the sensitive fields, and they\'re encrypted automatically.'); ?>
    <?php code_ref('src/Strategies.php', '<code>FieldLevel::SENSITIVE_FIELDS</code>. Try adding <code>\'email\'</code> to the list!'); ?>
<?php step_end(); ?>

<!-- 6 ------------------------------------------------------------------ -->
<?php step_start(6, 'HTTPS: the padlock in your browser', 'https'); ?>
    <p>HTTPS = normal web traffic (HTTP) wrapped in encryption (TLS). To turn it on, a web server needs a <b>certificate</b> containing its public key.
       Fun fact: this lab runs on plain <b><?= !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'HTTPS' : 'HTTP (not encrypted)' ?></b>, which is fine on your own computer but never OK for a public website.</p>
    <?php todo(['Press the button to create a certificate for <code>localhost</code>.', 'Read the "secure connection" steps from top to bottom.']); ?>
    <form method="post">
        <input type="hidden" name="action" value="https">
        <div class="inline">
            <div><label>Website name</label><input type="text" name="domain" value="<?= h(post('domain', 'localhost')) ?>"></div>
            <button>Create certificate & connect</button>
        </div>
    </form>
    <?php if (isset($out['cert'])): $c = $out['cert']; ?>
        <div class="output">
            <h3>The certificate (the website's ID card)</h3>
            <?php row('Issued to', $c['subject']); ?>
            <?php row('Issued by', $c['issuer'] . '  (itself = "self-signed", so browsers would warn)'); ?>
            <?php row('Valid', $c['validFrom'] . '  →  ' . $c['validTo']); ?>
            <?php row('Fingerprint (SHA-256)', $c['fingerprint']); ?>
            <details class="hint"><summary>Show the certificate file</summary><div><pre><?= h($c['certificatePem']) ?></pre></div></details>
            <h3>Setting up the secure connection (simplified)</h3>
            <table>
                <?php foreach ($out['tls'] as $n => [$who, $what]): ?>
                    <tr><td style="white-space:nowrap"><?= $n + 1 ?>. <b><?= h($who) ?></b></td><td><?= h($what) ?></td></tr>
                <?php endforeach; ?>
            </table>
            <?php explain('This is <b>hybrid encryption</b> from lesson 03 in action. The server\'s <b>public key</b> (from the certificate) is used once to safely share a random <b>AES</b> key. Then fast AES protects everything: your password, cookies, the pages. Real websites get certificates signed by a trusted authority such as Let\'s Encrypt, which is why your browser trusts them and shows the padlock.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('HTTPS = certificate (public key) to agree on a key + AES for the data.'); ?>
<?php step_end(); ?>

<!-- 7 ------------------------------------------------------------------ -->
<?php step_start(7, 'Link-level encryption: hop by hop', 'link',
    'Each connection ("link") between two devices has its own key, and may even use its own algorithm. Every router <b>decrypts</b> the message, then <b>re-encrypts</b> it for the next link.'); ?>
    <?php todo(['Press <b>Send</b> and follow the table row by row.', 'Look for the yellow rows: where can the message be read?']); ?>
    <form method="post">
        <input type="hidden" name="action" value="link">
        <label>Message</label>
        <input type="text" name="linkmsg" value="<?= h(post('linkmsg', 'Shipment #882 leaves Manila 06:00')) ?>">
        <button>Send through Router A and Router B</button>
    </form>
    <?php if (isset($out['link'])): ?>
        <div class="output table-wrap">
            <table>
                <tr><th>Where</th><th>What happens</th><th>Data at this point</th></tr>
                <?php foreach ($out['link'] as $step): ?>
                    <tr>
                        <td><b><?= h($step['node']) ?></b></td>
                        <td><?= h($step['action']) ?></td>
                        <td><code class="<?= !empty($step['exposed']) ? 'hl' : '' ?>"><?= h(shorten($step['data'], 60)) ?></code></td>
                    </tr>
                <?php endforeach; ?>
            </table>
            <?php explain('On every wire the message was encrypted, each time with a different key and algorithm (AES, then Twofish, then 3DES). But inside Router A and Router B (yellow) it was <b>plain text</b> for a moment. Anyone who controls a router could read it. That\'s the big difference from end-to-end encryption in step 4.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('link-level protects each wire, but every middle device sees the plaintext.'); ?>
<?php step_end(); ?>

<!-- 8 ------------------------------------------------------------------ -->
<?php step_start(8, 'Network-level encryption (like a VPN)', 'network',
    'Two office routers build an encrypted "tunnel" across the internet using IPsec. Every data packet is encrypted automatically. Apps don\'t need to change at all.'); ?>
    <?php todo(['Press <b>Send</b>.', 'Compare the packet inside the office with the packet on the internet. Which details are hidden?']); ?>
    <form method="post">
        <input type="hidden" name="action" value="network">
        <label>Data inside the packet</label>
        <input type="text" name="netmsg" value="<?= h(post('netmsg', 'SELECT * FROM payroll')) ?>">
        <button>Send through the tunnel</button>
    </form>
    <?php if (isset($out['net'])): $n = $out['net']; ?>
        <div class="output">
            <h3>1. The packet inside Office A</h3>
            <pre><?= h(json_encode($n['inner'], JSON_PRETTY_PRINT)) ?></pre>
            <h3>2. The same packet travelling over the internet</h3>
            <pre><?= h(json_encode(['outer_header' => $n['esp']['header'], 'encrypted_payload' => shorten($n['esp']['payload'], 70)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
            <?php row('3. Office B\'s router decrypts', json_encode($n['back']), 'good'); ?>
            <?php row('If someone alters the outer header', $out['netTamper'], 'good'); ?>
            <?php explain('On the internet, an eavesdropper sees only the two office routers\' addresses. The real computers, port and data are all encrypted. The outer header isn\'t secret, but it\'s protected against changes: when we altered it, the packet was rejected. This all happens at the <b>network layer</b>, below the apps, so every program is protected without any changes.'); ?>
        </div>
    <?php endif; ?>
    <?php remember('network-level (IPsec / VPN) encrypts all traffic between two networks automatically.'); ?>
<?php step_end(); ?>

<?php check_yourself([
    ['With BYOE, who holds the encryption key?', ['The cloud provider', 'The customer (you)', 'Nobody'], 1,
        'Bring Your Own Key: the provider only stores ciphertext.'],
    ['In end-to-end encryption, can the chat company\'s server read your messages?', ['Yes', 'No, only the sender and recipient can', 'Only on weekends'], 1,
        'Only the recipient\'s private key, on their own device, can decrypt.'],
    ['What is the main weakness of link-level encryption?', ['It is too slow', 'Each router in the middle briefly sees the plaintext', 'It needs no keys'], 1,
        'Data is decrypted and re-encrypted at every hop.'],
    ['What must a web server have before it can use HTTPS?', ['A public key certificate', 'A database', 'A VPN'], 0,
        'The certificate carries the server\'s public key and identity.'],
]); ?>

<?php page_footer(); ?>
