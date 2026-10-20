<?php
/**
 * bootstrap.php — loaded at the top of EVERY page.
 *
 * JS analogy: think of this as your app's "index.ts" that imports all your
 * modules and sets global config before anything else runs.
 *
 * In PHP, `require` (or `require_once`) literally pastes another file's code
 * in at that spot. `require_once` makes sure a file is only loaded once,
 * even if several pages ask for it (like ES modules being cached).
 */

declare(strict_types=1); // like TypeScript's "strict": PHP won't silently convert types for us

// Show every error while learning (you'd turn this off in production).
error_reporting(E_ALL);
ini_set('display_errors', '1');

// __DIR__ = the folder this file lives in (like `__dirname` in Node.js).
define('PROJECT_ROOT', dirname(__DIR__));

/*
 * Every student gets a PRIVATE storage folder for their keys, "cloud" files and database,
 * so when the lab is hosted online, students never see or overwrite each other's data.
 *
 * How: the first time a browser visits, we give it a random ID in a cookie
 * (like a "session ID"). Its folder is storage/students/<that ID>/.
 * In the terminal (php cli/run-all.php) there's no browser, so it uses storage/cli/.
 */
if (PHP_SAPI === 'cli') {
    $labId = 'cli';
    define('STORAGE_REL', 'storage/cli');
} else {
    $labId = $_COOKIE['lab_id'] ?? '';                       // $_COOKIE ~ req.cookies in Express
    if (!preg_match('/^[a-f0-9]{32}$/', $labId)) {           // missing or tampered -> make a new one
        $labId = bin2hex(random_bytes(16));
        setcookie('lab_id', $labId, [
            'expires'  => time() + 60 * 60 * 24 * 30,        // 30 days
            'path'     => '/',
            'httponly' => true,                              // JavaScript can't read it
            'samesite' => 'Lax',
        ]);
    }
    define('STORAGE_REL', 'storage/students/' . $labId);
}
define('STORAGE_DIR', PROJECT_ROOT . '/' . STORAGE_REL);   // where keys, the "cloud" and the DB live

// Make sure this student's storage folder exists (mkdir -p).
if (!is_dir(STORAGE_DIR)) {
    mkdir(STORAGE_DIR, 0700, true);
}

/** Show a storage path relative to the project, e.g. storage/students/ab12…/keys/x.key */
function storage_path(string $relative): string
{
    return STORAGE_REL . '/' . $relative;
}

/**
 * Housekeeping: about once every 50 page loads, delete student folders that
 * haven't been used for 2 days, so the server's disk doesn't fill up.
 */
if (PHP_SAPI !== 'cli' && random_int(1, 50) === 1) {
    foreach (glob(PROJECT_ROOT . '/storage/students/*', GLOB_ONLYDIR) ?: [] as $dir) {
        if (filemtime($dir) < time() - 2 * 24 * 3600 && $dir !== STORAGE_DIR) {
            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($files as $f) {
                $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
            }
            rmdir($dir);
        }
    }
}
touch(STORAGE_DIR); // mark this folder as recently used

// Third-party code (phpseclib) for DES, Blowfish and Twofish — see lib/vendor/autoload.php
require_once PROJECT_ROOT . '/lib/vendor/autoload.php';

// Our own code. Each file = one topic from the lesson.
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/KeyManager.php';
require_once __DIR__ . '/EncryptionEngine.php';
require_once __DIR__ . '/SymmetricCiphers.php';
require_once __DIR__ . '/AsymmetricCiphers.php';
require_once __DIR__ . '/Hashing.php';
require_once __DIR__ . '/Strategies.php';
require_once __DIR__ . '/Threats.php';

// One shared Key Manager for the whole app (the "Key Manager" component).
$keyManager = new KeyManager(STORAGE_DIR . '/keys');
