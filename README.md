# SafeBook

A small social app where the server is not trusted with your data.

Posts, messages, email and phone numbers are encrypted before they reach the
database. The key that opens them is wrapped by your password, so whoever
runs the server can hold the database file, the `.env`, and the disk they sit
on, and still not read a private post.

Built for **CSE447 Cryptography and Cryptanalysis** at BRAC University.
Django 5, SQLite, and the `cryptography` library.

---

## Running it

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python manage.py new_keys
```

Paste the two printed values into `.env`, then:

```bash
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

Open http://127.0.0.1:8000/. `seed_demo` prints three accounts and their
recovery codes, once.

---

## What is encrypted, and with which key

Two data keys per user, because there are two different things to defend
against.

| | protects | unwrapped by |
|---|---|---|
| **private DEK** | email, phone, the RSA private key, private posts, messages | your password, through scrypt |
| **server KEK** | the content key of each public post | the `.env` file |

A public post has to be readable by people who are not its author, so the
server is given a key for it. A private post is not, so it is not. The threat
model decides which key is used, and the difference shows up in the database:
a private post row carries one wrapped key, a public one carries two.

### Every post has its own key

```
post content  --AES-256-GCM-->  ciphertext
     ^
  post key  --wrapped with your DEK------>  key_owner    (always)
          \--wrapped with the server KEK->  key_public   (only when public)
```

Publishing adds a 60 byte wrapped key. Unpublishing removes it. The post
itself is never re-encrypted, and neither is anything else when you change
your password, which rewrites one envelope and nothing more. There is a test
for exactly that, because it is the claim envelope encryption exists to make.

### Messages

A fresh AES-256 session key per message, wrapped with the recipient's
RSA-2048 public key using OAEP. Their private key is itself AES-GCM
ciphertext under their DEK, so a message can only be opened by someone who
knows their password. A second wrapping under the sender's own public key is
what makes the Sent list readable; send anonymously and that second copy is
never made, so the sender cannot read it back either.

### Integrity

Every row carries an HMAC-SHA256 over a length-prefixed encoding of all its
ciphertext columns and the id of the account that owns it. GCM already
authenticates each field on its own; the row MAC is what stops fields being
swapped between rows, or a whole row being re-homed onto another user.

A row that fails either check is **not displayed**. Not displayed with a
warning next to it. A check whose failure still shows you the content is
decoration.

---

## Bugs found in the version I submitted

The original is the first commit in this repository. These were all
reproduced before they were fixed.

**The RSA layer bought nothing.** Every user's DEK was wrapped by the server
KEK, so the server could unwrap the DEK, decrypt the RSA private key with it,
unwrap the session key and read any message. `pwdwrap.py`, the scrypt module
meant to prevent exactly this, was in the repository and imported by nothing.
Wiring it up is most of what this rewrite is.

**Username enumeration by stopwatch.** `check_credentials` returned as soon
as it found no such user, skipping the Argon2 hash. Measured over 25
attempts: **93.15 ms for a real username against 0.49 ms for one that did not
exist, a 191x gap** and readable from a browser with no special tools. A miss
now hashes against a decoy record, and the same measurement afterwards gives
**1.01x**.

**MAC verification was decorative.** `mac_ok` was computed, passed to the
template and shown as a badge, while the plaintext was rendered underneath it
either way. Overwriting a stored MAC with 32 zero bytes still produced the
post on screen.

**The inbox crashed on its own data.** In `messages_inbox_view` the variables
`title` and `mac_ok` were only assigned inside `if m.is_asymmetric`. A
message without that flag raised `UnboundLocalError` on the first row, and on
any later row the loop variable still held **the previous message's decrypted
title**, which is worse than the crash. `message_detail_view` had the same
shape.

**Sending a message could silently do nothing.** If the recipient had no
public key, `message_new_view` fell out of the `if` with no `else`,
re-rendered the form, saved nothing, and reported nothing.

**The KEK rotation command corrupted the database.** `get_active_kek()`
returns `(kek, kek_id)` and the command unpacked it as `old_kek_id, old_kek`.
Past that, a second loop ran after the success message, re-wrapped every
envelope with the old KEK again, and rotated the DEKs without re-encrypting
any post, so every post became permanently unreadable. `rotate.txt`
documented a flag the command did not have.

Also: `logout` accepted GET; `DEBUG = True` was hardcoded at the bottom of
`settings.py`, past the line that read it from the environment; `"argon2"`
was listed in `INSTALLED_APPS`, where it does nothing; `keymgmt/services.py`
imported two functions and then defined functions over the top of them; and
there was no `.gitignore`, so a live `.env` and the database were one
`git add` away from being published.

---

## Security Lab

Five pages under `/lab/`, each running the experiment for one thing this app
claims. All of them use throwaway keys made when the page loads, and none of
them touch a real account.

**01 Block modes.** The same drawn padlock through ECB, CBC and GCM, with
repeated 16 byte blocks counted under each. The plaintext has 544 and the ECB
ciphertext has 544 as well, which is why the padlock is still visible in it.
CBC and GCM have none.

**02 Nonce reuse.** Two messages under one key and one nonce. XOR the
ciphertexts and the keystream cancels; XOR in the message you already knew
and the other comes out exactly, with no attack on AES at all. The same pair
with a fresh nonce each time returns nothing.

**03 Timing.** Three ways of comparing a 32 byte MAC, timed live. A hand
written byte loop climbs from roughly 370 ns to roughly 1960 ns as more of
the guess is right - a 5x slope, and enough to find a MAC in 8192 tries
rather than 2^256. Each figure is the fastest of thirteen runs rather than
the average, because interference can only add time and averaging folds the
machine being busy into the answer.

The page also reports the honest negative result: `==` on `bytes` drops into
`memcmp`, shows no usable slope at this size, and stays flat. That is a
measurement failing to find something rather than proof it is safe, and the
page says so - which is why SafeBook uses `compare_digest` anyway.

**04 Password storage.** MD5, SHA-256, scrypt and Argon2id timed on the
machine running them, with the cost of walking every six letter lowercase
password at each speed. Minutes against hundreds of days.

**05 Tampering.** Flip any byte of a stored row and watch the row MAC and the
GCM tag both refuse it, with the untouched row verifying beside them.

---

## Layout

```
safebook/settings.py       no secrets; everything comes from the environment
secureapp/
  crypto.py                AES-256-GCM, and wrapping one key inside another
  pwdwrap.py               scrypt at N=2^16, password to wrapping key
  keys.py                  which key protects what, and why there are two
  mac.py                   HMAC-SHA256 with a per-table HKDF context
  rsa_utils.py             RSA-2048 keypairs and OAEP wrapping
  recovery.py              the one time recovery code
  session_keys.py          holding the DEK for one login, split in two
  auth_utils.py            constant time credential check, lockout
  models.py                Account, Post, Message, LoginAttempt
  views.py                 no path here reads data without the user's key
  lab.py                   the five experiments
  admin.py                 every encrypted column, shown as hex
keymgmt/
  services.py              reading and validating the server KEK
  management/commands/     new_keys, rotate_kek
```

### Where the key lives during a session

The DEK is needed on every request after login, so it has to be held
somewhere. Django's session table is in the database, and the database is
what an attacker is assumed to have taken. So it is split: the browser cookie
holds a random 32 byte session key, and the session row holds the DEK
encrypted under it. A stolen database is ciphertext with no key; a stolen
cookie is a key with no ciphertext.

---

## Tests

```bash
python manage.py test
```

**87 tests, all passing**, grouped by what each one defends:

- `test_primitives.py` - AAD binding, fresh nonces, MAC domain separation,
  length prefix collisions, scrypt salting
- `test_auth.py` - the timing parity above, lockout, identical wording for
  real and invented usernames, POST only logout
- `test_confidentiality.py` - the server KEK refusing to open a private post,
  plaintext absent from the row, IDOR on posts and messages, the feed
  carrying only what was published
- `test_integrity.py` - a flipped byte and a wrecked MAC both keeping content
  off the screen, a row re-homed onto another user failing to verify
- `test_key_management.py` - a password change and a recovery both leaving
  every ciphertext byte untouched, a spent recovery code, KEK rotation and
  its dry run
- `test_lab.py` - the numbers the lab pages print, asserted

---

## Known limits

- **This is not end to end encryption.** The server sees your plaintext while
  you are signed in, because it is a server rendered Django app and the
  decryption happens there. What it cannot do is read anything while you are
  signed out. Real end to end would mean doing the crypto in the browser and
  never sending the key, which is a different application.
- **A public post is readable by the server.** That is the deal you make by
  publishing it, and the app says so at the point where you make it.
- **The recovery code is the whole account.** Anyone holding it can set a new
  password and open everything. It is shown once and never stored in a form
  that can be read back.
- **scrypt at N=2^16** costs about 280 ms per derivation on my laptop. That
  is deliberate: it is felt once at login, and multiplied by every guess an
  attacker makes.
- SQLite and the Django development server, neither of which belongs in
  production.
