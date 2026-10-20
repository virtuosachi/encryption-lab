<?php
/**
 * index.php — the home page (http://localhost:8000/).
 *
 * How a PHP page works (vs. a JS app):
 *   - The browser requests /index.php, PHP RUNS this file top-to-bottom on the
 *     server and sends back whatever HTML it printed.
 *   - Text outside <?php ... ?> tags is sent as-is (like a template literal).
 *   - `<?= $x ?>` prints a value (like `${x}` in a template string).
 */

require __DIR__ . '/../src/bootstrap.php';

// Quick environment check so students immediately see if something is missing.
$checks = [
    'PHP ' . PHP_VERSION . ' (need 8.1 or newer)' => version_compare(PHP_VERSION, '8.1.0', '>='),
    'OpenSSL extension (AES, 3DES, RSA, ECC, certificates)' => extension_loaded('openssl'),
    'Sodium extension (X25519, end-to-end encryption, BLAKE2b)' => extension_loaded('sodium'),
    'PDO SQLite extension (database encryption demo)' => extension_loaded('pdo_sqlite'),
    'Storage folder is writable' => is_writable(STORAGE_DIR),
];
$allOk = !in_array(false, $checks, true);

page_header('Welcome to the Encryption Lab',
    'A guided, hands-on tour of encryption and decryption. You don\'t need to know any cryptography — just follow the steps.');
?>

<section class="card" data-tour-title="What is this lab?" data-tour-text="A quick intro: encryption turns a message into secret code using a key, and decryption turns it back.">
    <h2>Start here</h2>
    <p>Imagine writing a note to a friend in a secret code that only the two of you understand. If someone else picks it up, it looks like gibberish. That's <b>encryption</b>. Turning the gibberish back into the note is <b>decryption</b>. The secret that makes it work is called the <b>key</b>.</p>
    <div class="flow">
        <span class="box plain">Hello!</span><span class="arrow">→ encrypt with key →</span>
        <span class="box cipher">x9$Lq#2v…</span><span class="arrow">→ decrypt with key →</span>
        <span class="box plain">Hello!</span>
    </div>
    <p>Your phone does this thousands of times a day: online banking, messaging apps, HTTPS websites, saved passwords. In this lab you'll do it yourself, with real code.</p>
</section>

<section class="card" data-tour-title="How the lessons work" data-tour-text="Every lesson is a list of short steps. These coloured boxes tell you what to do, explain your results, and suggest experiments.">
    <h2>How each lesson works</h2>
    <p>Every lesson is a list of short <b>steps</b>. Do them in order. Inside each step you'll see these boxes:</p>
    <div class="guide todo"><b>What to do</b>Exactly what to type and which button to press.</div>
    <div class="guide explain"><b>What just happened?</b>Appears after you press the button and explains the result in plain words.</div>
    <div class="guide challenge"><b>Try this next</b>Small experiments. This is where the real understanding happens, so don't skip them.</div>
    <div class="guide remember"><b>Remember:</b> the one idea to take away from the step.</div>
    <p>When you're done with a step, tick <b>"I finished this step"</b>. Your progress is saved in this browser and shown below. Each lesson ends with a short quiz.</p>
    <p class="explain">Curious about the code? Each step names the PHP file that did the work (look for "See the code"). You don't need to read the code to follow along.</p>
</section>

<section class="card" data-tour-title="Your lessons" data-tour-text="Do them in order, from 01 to 07. The badge on the right shows your progress in each lesson.">
    <h2>Lessons</h2>
    <p class="explain">Go in order: each lesson builds on the one before.</p>
    <ul class="lessons">
        <?php foreach (LESSONS as $file => [$num, $name, $desc, $minutes]): ?>
            <li data-lesson="<?= h($file) ?>"><a href="/<?= h($file) ?>">
                <span class="num"><?= h($num) ?></span>
                <span><b><?= h($name) ?></b><small><?= h($desc) ?></small></span>
                <span class="meta"><span class="badge" data-lesson-status>Not started</span><small class="explain">~<?= (int) $minutes ?> min</small></span>
            </a></li>
        <?php endforeach; ?>
    </ul>
</section>

<section class="card" data-tour-title="Setup check" data-tour-text="If everything here says OK, you are ready. If something says Missing, ask your instructor.">
    <h2>Is everything ready?</h2>
    <?php notice($allOk ? 'All good: you can start lesson 01.' : 'Something is missing. Ask your instructor or see the Troubleshooting section in README.md.', $allOk ? 'success' : 'error'); ?>
    <table>
        <?php foreach ($checks as $label => $passed): ?>
            <tr>
                <td><?= h($label) ?></td>
                <td><?= $passed ? '<span class="badge good">OK</span>' : '<span class="badge bad">Missing</span>' ?></td>
            </tr>
        <?php endforeach; ?>
    </table>
    <p class="explain">The lab saves keys, a pretend "cloud" folder and a small database in your own private folder, <code><?= h(STORAGE_REL) ?></code>. Each browser gets its own folder, so students never see each other's data. Delete the <code>storage</code> folder any time to start fresh.</p>
</section>

<?php page_footer(); ?>
