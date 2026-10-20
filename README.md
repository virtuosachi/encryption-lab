# Encryption Lab — a guided, hands-on PHP demo of encryption and decryption

A step-by-step web lab for beginners. Students follow numbered steps, type their own data,
press buttons and see real encryption happen, with plain-language explanations of every result.
No XAMPP, no Apache, no MySQL, no Composer. You only need **PHP 8.1 or newer**: it has its own
built-in web server.

---

## 1. Install PHP (one time)

**macOS** (needs [Homebrew](https://brew.sh)):

```bash
brew install php
php -v          # should print PHP 8.x
```

**Windows**: download the "VS17 x64 Thread Safe" zip from <https://windows.php.net/download>,
unzip it to `C:\php`, add `C:\php` to your PATH, copy `php.ini-development` to `php.ini`, and in
`php.ini` remove the `;` in front of these lines: `extension=openssl`, `extension=sodium`,
`extension=pdo_sqlite`.

**Linux (Ubuntu/Debian)**: `sudo apt install php-cli php-sqlite3`

## 2. Run the lab

Open a terminal **in this folder** and run:

```bash
php -S localhost:8000 -t public
```

Then open **http://localhost:8000** in your browser. Stop the server with `Ctrl + C`.

(On macOS/Linux you can also run `./start.sh`.)

What that command means:

| Part | Meaning | Node.js equivalent |
|---|---|---|
| `php -S localhost:8000` | Start PHP's built-in web server on port 8000 | `npx serve -l 8000` / `app.listen(8000)` |
| `-t public` | Serve files from the `public/` folder (the "document root") | `express.static('public')` |

Only `public/` is reachable from the browser. Your keys and code in `storage/` and `src/` are not.

### Prefer the terminal?

```bash
php cli/run-all.php
```

This runs every demo from every lesson and prints PASS/FAIL. It's the fastest way to check that your PHP has everything it needs.

---

## 3. Put it online for free (Render)

You can host the lab for free on [Render](https://render.com) so students only need a link.
The project already includes everything Render needs: `Dockerfile` (runs the lab with the
Apache web server, so a whole class can use it at once) and `render.yaml` (the settings).

**What "free" means on Render:** no charges and no monthly credit to run out. The trade-offs:
- After **15 minutes with no visitors**, the app goes to sleep. The next visit wakes it up in about **1 minute**.
  **Tip:** open the link yourself a couple of minutes before class.
- Saved data (keys, "cloud" files, database rows) is **wiped** whenever the app sleeps or restarts.
  That's fine here: every student starts with a fresh lab anyway.
- 750 free hours per month: enough to keep one app running all month.

### Step A — Put the project on GitHub (one time)

Render deploys straight from a GitHub repository.

1. Create a free account at <https://github.com> and click **New repository**. Name it `encryption-lab`.
   It can be Public or Private.
2. Upload the project, using **either** option:
   - **Easiest (no commands):** on the new repo page, click **uploading an existing file**, then drag in
     **everything inside** the `encryption-demo` folder (`public`, `src`, `lib`, `cli`, `Dockerfile`, `render.yaml`,
     `README.md`, `start.sh`). Don't upload the `storage` folder. Click **Commit changes**.
   - **With git in a terminal**, inside the `encryption-demo` folder:
     ```bash
     git init
     git add .
     git commit -m "Encryption Lab"
     git branch -M main
     git remote add origin https://github.com/YOUR-USERNAME/encryption-lab.git
     git push -u origin main
     ```

### Step B — Deploy on Render

1. Sign up at <https://render.com> with your GitHub account (free).
2. Click **New** → **Blueprint**, choose your `encryption-lab` repository, and click **Apply**.
   Render reads `render.yaml` and creates a **free** web service called `encryption-lab`.
   (Alternative: **New** → **Web Service** → pick the repo → Language **Docker** → Instance type **Free** → **Deploy**.)
3. Wait for the first build (a few minutes). When it says **Live**, your link appears at the top, e.g.
   `https://encryption-lab-xxxx.onrender.com`. Share that link with your students.

### Updating the online version

Change files, upload them to GitHub again (or `git push`), and Render redeploys automatically.

### Is students' data private?

Yes. Each browser gets its own private storage folder (a random ID saved in a cookie), so students never
see each other's keys, files or database rows. Progress ticks and tour settings are stored in each
student's own browser.

---

## 4. What's inside

```
encryption-demo/
├── public/                      ← web pages (one per lesson)
│   ├── index.php                  "Start here" page, lesson list with progress, environment check
│   ├── 01-basics.php              plaintext, ciphertext, keys, the 3 components
│   ├── 02-symmetric.php           AES, DES, 3DES, Blowfish, Twofish
│   ├── 03-asymmetric.php          RSA, signatures, Diffie-Hellman, ECC, ElGamal, speed race
│   ├── 04-hashing.php             MD5, SHA-1/2/3, BLAKE2b, integrity, passwords
│   ├── 05-security-goals.php      confidentiality, integrity, authentication, nonrepudiation, availability
│   ├── 06-strategies.php          BYOE, cloud, column, E2EE, field, HTTPS, link, network
│   ├── 07-threats.php             brute force, timing side channel, cryptanalysis, backdoor
│   └── assets/
│       ├── style.css
│       ├── guide.js               progress, quizzes, and sending forms without reloading the page
│       └── tour.js                the pop-up guided tour
├── src/                         ← the actual crypto code (read these!)
│   ├── bootstrap.php              loads everything (like index.ts)
│   ├── helpers.php                h(), post(), page layout, guided-mode building blocks
│   ├── KeyManager.php             component 3: "Key Manager"
│   ├── EncryptionEngine.php       component 2: "Encryption Engine" (AES-256-GCM)
│   ├── SymmetricCiphers.php       AES, DES, 3DES, Blowfish, Twofish
│   ├── AsymmetricCiphers.php      RSA, ECC (ECDSA/ECDH), Diffie-Hellman, ElGamal
│   ├── Hashing.php                MD5, SHA-1, SHA-256/512, SHA-3, BLAKE2b, HMAC, passwords
│   ├── Strategies.php             BYOE, cloud, column, E2EE, field, HTTPS, link, network
│   └── Threats.php                brute force, timing attack, ECB/birthday, backdoor
├── Dockerfile                   ← used when hosting online (Apache + PHP)
├── render.yaml                  ← Render settings (free plan)
├── cli/run-all.php              ← run every demo in the terminal
├── lib/vendor/                  ← bundled phpseclib (only for DES, Blowfish, Twofish)
└── storage/                     ← created automatically: one private folder per student (keys, "cloud" files, SQLite DB)
```

### How the guided lessons work

Each lesson page has the same structure, so students always know what to do:

| Element | What it's for |
|---|---|
| **In this lesson you will…** / **Words to know** | Goals and new vocabulary, at the top |
| **Step 1, Step 2, …** cards | Do them in order; each has a form to try |
| **What to do** | Exact instructions: what to type, which button to press |
| **What just happened?** | Appears after the button is pressed and explains the result in plain words |
| **Try this next** | Small experiments that deepen understanding |
| **Need a hint?** | Help when something goes wrong |
| **Remember** | The one-line takeaway |
| **Check yourself** | Short multiple-choice quiz at the end, checked instantly |
| "I finished this step" | Progress tick, saved in the browser; the home page shows progress per lesson |
| **Guided tour** pop-ups | Offered automatically on a student's first visit to each page. Highlights one step at a time with Back / Next / Skip, and points to the explanation as soon as a result appears. Can be minimized, skipped, or turned off ("Don't open tours automatically"). The **Guide me** button (bottom-right) restarts it from the step currently on screen. Keyboard: arrows = Back/Next, Esc = close. |

For teachers and curious students, each step also names the PHP file that did the work (**See the code**).
Every function in `src/` is commented.

### Where each topic lives in the code

| Topic | Lesson | Code |
|---|---|---|
| Plaintext / ciphertext, data + engine + key manager | 01 | `EncryptionEngine.php`, `KeyManager.php` |
| Symmetric: AES, DES, 3DES, Blowfish, Twofish | 02 | `SymmetricCiphers.php` |
| Asymmetric: RSA, signatures, Diffie-Hellman, ECC, ElGamal; speed comparison | 03 | `AsymmetricCiphers.php` |
| Hashing: MD5, SHA-1, SHA-256/512, SHA-3, BLAKE2b; integrity; passwords | 04 | `Hashing.php` |
| Confidentiality, integrity, authentication, nonrepudiation, availability | 05 | reuses the above |
| BYOE, cloud storage, column-level, E2EE, field-level, HTTPS, link-level, network-level | 06 | `Strategies.php` |
| Brute force, side channel, cryptanalysis, backdoors | 07 | `Threats.php` |

**Resetting progress:** the step ticks live in the browser's local storage. Clear the site data for `localhost:8000` to reset them.

---

## 5. PHP cheat sheet for JavaScript / TypeScript developers

| PHP | JavaScript / TypeScript |
|---|---|
| `$name = 'Ana';` | `let name = 'Ana';` |
| `'Hi ' . $name` (dot joins strings) | `'Hi ' + name` |
| `"Hi $name"` (double quotes interpolate) | `` `Hi ${name}` `` |
| `$s .= 'x';` | `s += 'x';` |
| `function add(int $a, int $b): int {}` | `function add(a: number, b: number): number {}` |
| `?string` | `string \| null` |
| `$list = ['a', 'b'];` `$list[] = 'c';` | `const list = ['a','b']; list.push('c');` |
| `$obj = ['key' => 'value'];` `$obj['key']` | `const obj = { key: 'value' }; obj.key` |
| `foreach ($obj as $k => $v) {}` | `for (const [k, v] of Object.entries(obj)) {}` |
| `count($list)` / `strlen($str)` | `list.length` / `str.length` |
| `$a ?? 'default'` | `a ?? 'default'` |
| `$user?->name` | `user?.name` |
| `fn ($x) => $x * 2` | `(x) => x * 2` |
| `function () use ($key) { ... }` | closures capture automatically in JS; PHP needs `use` |
| `match ($x) { 'a' => 1, default => 0 }` | a `switch` that returns a value |
| `$obj->method()` / `Class::staticMethod()` | `obj.method()` / `Class.staticMethod()` |
| `new KeyManager($dir)` | `new KeyManager(dir)` |
| `require 'file.php';` | `import './file'` (it pastes the file in) |
| `use phpseclib3\Crypt\Twofish;` | `import { Twofish } from 'phpseclib3/Crypt'` |
| `echo $x;` / `<?= $x ?>` | `console.log(x)` / `${x}` in a template |
| `$_POST['field']` | `req.body.field` (Express) |
| `json_encode($a)` / `json_decode($s, true)` | `JSON.stringify(a)` / `JSON.parse(s)` |
| `try {} catch (Throwable $e) { $e->getMessage(); }` | `try {} catch (e) { e.message }` |
| `htmlspecialchars($s)` (our `h($s)`) | `el.textContent = s` (escapes HTML) |

### Crypto functions you'll see, and their Node.js equivalents

| PHP | Node.js (`crypto` module) |
|---|---|
| `random_bytes(32)` | `crypto.randomBytes(32)` |
| `bin2hex($b)` / `hex2bin($h)` | `buf.toString('hex')` / `Buffer.from(h, 'hex')` |
| `base64_encode($b)` / `base64_decode($s)` | `buf.toString('base64')` / `Buffer.from(s, 'base64')` |
| `openssl_encrypt($pt, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag)` | `crypto.createCipheriv('aes-256-gcm', key, iv)` |
| `openssl_pkey_new([...])` | `crypto.generateKeyPairSync('rsa', {...})` |
| `openssl_public_encrypt()` / `openssl_private_decrypt()` | `crypto.publicEncrypt()` / `crypto.privateDecrypt()` |
| `openssl_sign()` / `openssl_verify()` | `crypto.sign()` / `crypto.verify()` |
| `hash('sha256', $s)` | `crypto.createHash('sha256').update(s).digest('hex')` |
| `hash_hmac('sha256', $s, $key)` | `crypto.createHmac('sha256', key).update(s).digest('hex')` |
| `hash_equals($a, $b)` | `crypto.timingSafeEqual(a, b)` |
| `hash_pbkdf2(...)` | `crypto.pbkdf2Sync(...)` |
| `password_hash()` / `password_verify()` | `bcrypt.hash()` / `bcrypt.compare()` (npm) |
| `sodium_crypto_box(...)` | `libsodium-wrappers` (npm) / `tweetnacl` |

---

## 6. Notes

**Why is there a `lib/vendor/` folder?** Modern OpenSSL 3 (used by current PHP builds) switches
off **DES** and **Blowfish** because they're insecure, and PHP has never included **Twofish**.
So those three use the pure-PHP library [phpseclib](https://phpseclib.com) (MIT license), bundled
so you don't need Composer. Everything else uses PHP's built-in `openssl`, `sodium` and `hash`.

**Resetting the lab:** stop the server and delete the `storage/` folder. It's recreated on the next page load. Each browser uses its own subfolder, `storage/students/<random id>/`. Folders unused for 2 days are cleaned up automatically.

**Is this production-ready?** `EncryptionEngine` (AES-256-GCM with random IVs) is a correct,
standard construction. The rest is built to teach: keys sit in plain files, and the Diffie-Hellman
and ElGamal demos use tiny numbers on purpose. Real systems keep keys in a key-management service (AWS KMS, Azure Key Vault, an HSM).

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `php: command not found` | PHP isn't installed or isn't on your PATH (see step 1). On macOS, open a new terminal after `brew install php`. |
| `Address already in use` | Port 8000 is busy. Use another one: `php -S localhost:8080 -t public` |
| Home page shows **Missing** for an extension | Windows: enable it in `php.ini` (step 1). macOS Homebrew PHP includes them all. |
| `Could not generate RSA keys` (mostly Windows) | Set the env var `OPENSSL_CONF` to the `openssl.cnf` in your PHP folder (e.g. `C:\php\extras\ssl\openssl.cnf`), then restart the terminal. |
| `Storage folder is writable: Missing` | Run the server from a folder you own, or `chmod -R u+w storage` |
| Timing-attack demo guessed wrong | It measures real time, so a busy laptop or server adds noise. Just run it again. |
| Online link takes ~1 minute to open | The free Render app was asleep. It wakes up on the first visit, so open it before class. |
| Render build fails | Check that `Dockerfile` is at the top level of the GitHub repo, not inside a sub-folder. |
