<?php
/**
 * Tiny autoloader for the bundled third-party code (no Composer needed).
 *
 * JS analogy: this is like a mini "module resolver". When PHP meets a class
 * it hasn't loaded yet (e.g. `new \phpseclib3\Crypt\Twofish()`), it calls
 * this function, which maps the class name to a file path and require()s it.
 *
 * Bundled libraries (MIT licensed, see LICENSE files next to them):
 *   - phpseclib 3.0.47 (only the DES, 3DES, Blowfish and Twofish parts)
 *   - paragonie/constant_time_encoding 2.7.0
 */
spl_autoload_register(function (string $class): void {
    $map = [
        'phpseclib3\\'         => __DIR__ . '/phpseclib/',
        'ParagonIE\\ConstantTime\\' => __DIR__ . '/paragonie/ConstantTime/',
    ];
    foreach ($map as $prefix => $dir) {
        if (str_starts_with($class, $prefix)) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
            return;
        }
    }
});
