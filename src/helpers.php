<?php
/**
 * helpers.php — small utility functions, the shared page layout, and the
 * "guided mode" building blocks (step cards, hints, explanations, quizzes).
 *
 * PHP syntax reminders for JS/TS developers:
 *   - Variables start with $          ->  $name = 'Ana';        (JS: let name = 'Ana')
 *   - String concatenation uses .     ->  'Hi ' . $name         (JS: 'Hi ' + name)
 *   - Type hints are like TS types    ->  function f(string $s): int
 *   - ?string means "string or null"  ->  (TS: string | null)
 *   - Arrays are both lists AND objects: ['a', 'b']  or  ['key' => 'value']
 */

declare(strict_types=1);

/**
 * The list of lessons, used to build the menu and the home page.
 * Each entry: file => [number, title, one-line description, estimated minutes]
 */
const LESSONS = [
    '01-basics.php'         => ['01', 'Encryption Basics', 'Turn readable text into secret code and back again.', 10],
    '02-symmetric.php'      => ['02', 'Symmetric Encryption', 'One shared key locks and unlocks: AES, DES, 3DES, Blowfish, Twofish.', 15],
    '03-asymmetric.php'     => ['03', 'Asymmetric Encryption', 'Public and private keys: RSA, ECC, Diffie-Hellman, digital signatures, ElGamal.', 20],
    '04-hashing.php'        => ['04', 'Hashing', 'One-way fingerprints: MD5, SHA-1, SHA-2, SHA-3, BLAKE.', 15],
    '05-security-goals.php' => ['05', 'What Encryption Protects', 'Confidentiality, integrity, authentication, nonrepudiation, availability.', 15],
    '06-strategies.php'     => ['06', 'Encryption in the Real World', 'BYOE, cloud, database, end-to-end, web forms, HTTPS, links and networks.', 25],
    '07-threats.php'        => ['07', 'Attacks on Encryption', 'Brute force, timing side channels, cryptanalysis and backdoors.', 20],
];

/**
 * Escape text before printing it into HTML (prevents XSS).
 * JS analogy: like setting element.textContent instead of innerHTML.
 * ALWAYS wrap user input with h() when echoing it.
 */
function h(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

/**
 * Read a field from a submitted form.
 * $_POST is a built-in "superglobal" array holding form data
 * (Express analogy: req.body). `??` works exactly like JS's nullish coalescing.
 */
function post(string $key, string $default = ''): string
{
    return trim((string) ($_POST[$key] ?? $default));
}

/** Which button was clicked? Every form in this project sends a hidden "action" field. */
function action(): string
{
    return $_SERVER['REQUEST_METHOD'] === 'POST' ? post('action') : '';
}

/** Turn raw bytes into readable hex, e.g. "\x01\xAB" -> "01ab". (JS: Buffer.toString('hex')) */
function hex(string $bytes): string
{
    return bin2hex($bytes);
}

/** Shorten long strings for display: "abcdef...xyz (300 chars)". */
function shorten(string $text, int $max = 90): string
{
    if (strlen($text) <= $max) {
        return $text;
    }
    return substr($text, 0, $max) . '… (' . strlen($text) . ' chars total)';
}

/**
 * Measure how long a function takes, in milliseconds.
 * `callable` = any function (like a TS `() => T`). Returns [result, ms].
 */
function timed(callable $fn): array
{
    $start  = hrtime(true);                // nanoseconds (like performance.now() but in ns)
    $result = $fn();
    $ms     = (hrtime(true) - $start) / 1e6;
    return [$result, $ms];
}

/** Print a labelled output row. `<?= ?>` in templates is shorthand for `<?php echo ?>`. */
function row(string $label, string $value, string $class = ''): void
{
    echo '<div class="row ' . h($class) . '"><span class="label">' . h($label) . '</span>'
       . '<code class="value">' . h($value) . '</code></div>';
}

/** Show a success / error / info message box. */
function notice(string $message, string $type = 'info'): void
{
    echo '<div class="notice ' . h($type) . '">' . $message . '</div>';
}

/* ==========================================================================
 * GUIDED MODE building blocks.
 * Each lesson page is a sequence of numbered STEPS. Inside each step:
 *   todo()      -> "What to do"            (instructions BEFORE pressing a button)
 *   explain()   -> "What just happened?"    (shown AFTER the result appears)
 *   challenge() -> "Try this next"          (small experiments to deepen understanding)
 *   remember()  -> "Remember"               (the one-sentence takeaway)
 * And at the end of the page: check_yourself() -> a mini quiz with hidden answers.
 * Progress ("I finished this step") is saved in the browser by assets/guide.js.
 * ======================================================================== */

/** Top of a lesson: what you'll learn + new words, with simple definitions. */
function lesson_intro(array $goals, array $words = []): void
{ ?>
    <section class="card intro">
        <div class="intro-grid">
            <div>
                <h2>In this lesson you will…</h2>
                <ul class="goals"><?php foreach ($goals as $g): ?><li><?= $g ?></li><?php endforeach; ?></ul>
            </div>
            <?php if ($words): ?>
            <div>
                <h2>Words to know</h2>
                <dl class="words">
                    <?php foreach ($words as $term => $meaning): ?>
                        <dt><?= h($term) ?></dt><dd><?= $meaning ?></dd>
                    <?php endforeach; ?>
                </dl>
            </div>
            <?php endif; ?>
        </div>
        <div class="progress" data-progress>
            <div class="progress-bar"><span></span></div>
            <small><span data-progress-text>0</span> steps finished</small>
        </div>
    </section>
<?php }

/** Open a numbered step card. Pair with step_end(). $id makes the anchor + progress key. */
function step_start(int $number, string $title, string $id, string $intro = ''): void
{ ?>
    <section class="card step" id="<?= h($id) ?>" data-step="<?= h($id) ?>">
        <div class="step-head">
            <span class="step-num">Step <?= $number ?></span>
            <h2><?= h($title) ?></h2>
        </div>
        <?php if ($intro !== ''): ?><p class="lead"><?= $intro ?></p><?php endif; ?>
<?php }

function step_end(): void
{ ?>
        <label class="done-check"><input type="checkbox" data-done> I finished this step</label>
    </section>
<?php }

/** "What to do" — numbered instructions. */
function todo(array $instructions): void
{ ?>
    <div class="guide todo">
        <b>What to do</b>
        <ol><?php foreach ($instructions as $i): ?><li><?= $i ?></li><?php endforeach; ?></ol>
    </div>
<?php }

/** "What just happened?" — explanation shown under a result. */
function explain(string $html): void
{
    echo '<div class="guide explain"><b>What just happened?</b><div>' . $html . '</div></div>';
}

/** "Try this next" — small experiments. */
function challenge(array $ideas): void
{ ?>
    <div class="guide challenge">
        <b>Try this next</b>
        <ul><?php foreach ($ideas as $i): ?><li><?= $i ?></li><?php endforeach; ?></ul>
    </div>
<?php }

/** "Remember" — the key takeaway. */
function remember(string $html): void
{
    echo '<div class="guide remember"><b>Remember:</b> ' . $html . '</div>';
}

/** A hint the student can open if stuck (uses the native <details> element, no JS). */
function hint(string $html, string $label = 'Need a hint?'): void
{
    echo '<details class="hint"><summary>' . h($label) . '</summary><div>' . $html . '</div></details>';
}

/** Point students to the PHP code that did the work. */
function code_ref(string $file, string $what): void
{
    echo '<p class="code-ref"><b>See the code:</b> <code>' . h($file) . '</code> — ' . $what . '</p>';
}

/**
 * End-of-lesson quiz. Each item: ['question', ['A', 'B', 'C'], correctIndex, 'why'].
 * Answers are checked in the browser by guide.js (nothing is sent to the server).
 */
function check_yourself(array $questions): void
{ ?>
    <section class="card quiz" data-step="quiz">
        <div class="step-head"><span class="step-num">Quiz</span><h2>Check yourself</h2></div>
        <p class="lead">Pick an answer for each question. You'll see right away if you got it.</p>
        <?php foreach ($questions as $qi => [$question, $options, $correct, $why]): ?>
            <div class="q" data-correct="<?= (int) $correct ?>">
                <p><b><?= $qi + 1 ?>. <?= $question ?></b></p>
                <?php foreach ($options as $oi => $opt): ?>
                    <button type="button" class="opt" data-i="<?= $oi ?>"><?= $opt ?></button>
                <?php endforeach; ?>
                <p class="why" hidden><?= $why ?></p>
            </div>
        <?php endforeach; ?>
        <label class="done-check"><input type="checkbox" data-done> I finished the quiz</label>
    </section>
<?php }

/**
 * URL of a file in public/assets with a "?v=<last modified time>" suffix.
 * This "cache-busting" trick makes the browser download the file again whenever
 * it changes, instead of using an old copy it saved earlier.
 */
function asset(string $file): string
{
    $path = PROJECT_ROOT . '/public/assets/' . $file;
    return '/assets/' . $file . '?v=' . (is_file($path) ? filemtime($path) : 0);
}

/* --------------------------------------------------------------------------
 * Page layout. Every lesson page calls page_header() at the top and
 * page_footer() at the bottom — like a React <Layout> wrapper.
 * ------------------------------------------------------------------------ */

function page_header(string $title, string $subtitle = ''): void
{
    $current = basename($_SERVER['SCRIPT_NAME'] ?? '');
    ?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= h($title) ?> · Encryption Lab</title>
    <link rel="stylesheet" href="<?= asset('style.css') ?>">
    <script src="<?= asset('guide.js') ?>" defer></script>
    <script src="<?= asset('tour.js') ?>" defer></script>
</head>
<body data-page="<?= h($current) ?>">
<header class="topbar">
    <a class="brand" href="/">Encryption Lab <small>a guided hands-on demo</small></a>
    <nav>
        <?php foreach (LESSONS as $file => [$num, $name]): ?>
            <a href="/<?= h($file) ?>" class="<?= $current === $file ? 'active' : '' ?>" title="<?= h($name) ?>"><?= h($num) ?></a>
        <?php endforeach; ?>
    </nav>
</header>
<main>
    <?php if (isset(LESSONS[$current])): ?>
        <p class="crumb"><a href="/">Home</a> › Lesson <?= h(LESSONS[$current][0]) ?> of <?= count(LESSONS) ?> · about <?= (int) LESSONS[$current][3] ?> minutes</p>
    <?php endif; ?>
    <h1><?= h($title) ?></h1>
    <?php if ($subtitle !== ''): ?><p class="subtitle"><?= $subtitle ?></p><?php endif; ?>
    <?php
}

function page_footer(): void
{
    $current = basename($_SERVER['SCRIPT_NAME'] ?? '');
    $files   = array_keys(LESSONS);
    $i       = array_search($current, $files, true);
    ?>
    <footer class="pager">
        <?php if ($i !== false && $i > 0): ?>
            <a href="/<?= h($files[$i - 1]) ?>">← <?= h(LESSONS[$files[$i - 1]][1]) ?></a>
        <?php else: ?><a href="/">← Home</a><?php endif; ?>
        <?php if ($i !== false && $i < count($files) - 1): ?>
            <a class="next" href="/<?= h($files[$i + 1]) ?>">Next: <?= h(LESSONS[$files[$i + 1]][1]) ?> →</a>
        <?php elseif ($i === false): ?>
            <a class="next" href="/<?= h($files[0]) ?>">Start lesson 01 →</a>
        <?php else: ?>
            <a class="next" href="/">Finish — back to Home</a>
        <?php endif; ?>
    </footer>
</main>
</body>
</html>
    <?php
}
