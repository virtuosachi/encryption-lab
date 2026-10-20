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
define('STORAGE_DIR', PROJECT_ROOT . '/storage');   // where keys, the "cloud" and the DB live

// Make sure the storage folder exists (mkdir -p).
if (!is_dir(STORAGE_DIR)) {
    mkdir(STORAGE_DIR, 0700, true);
}

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
