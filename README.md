# SafeBook

A social network where the server keeps no key to your posts.

It works like the apps you already use: friends, a news feed, posts, comments,
likes, profiles and chat. The difference is underneath. Every post is
encrypted with a key of its own, and copies of that key go only to the people
allowed to read it: you, your friends, or, for a public post, the server. A
friends-only post, the comments under it and every chat message are stored as
ciphertext that nobody at SafeBook holds a key to, even with the database, the
`.env` and the disk they sit on.

Built for **CSE447 Cryptography and Cryptanalysis** at BRAC University.
Django 5, SQLite, and the `cryptography` library.

---

## Running it

On Windows, double-click **`RUN-SafeBook.bat`**. It builds the virtual
environment, writes a `.env` with fresh keys the first time, loads the demo
people and opens http://127.0.0.1:8010/ (8010, so it can run beside
Rentorium, which uses 8000).

By hand:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python manage.py new_keys --write      # fills in both keys
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

`seed_demo` prints four accounts and their recovery codes, once. Run it with
`--reset` to rebuild them.

### Trying it

The front page and the sign in page show the demo people as cards. Pick one
and you are signed in as them, with their friends, posts and chats.

| Person | Username | Password | Worth looking at |
|---|---|---|---|
| Nusrat Jahan | `nusrat` | `Nusrat#2026safe` | friends with everyone; has an only-me post |
| Faiaz Rahman | `faiaz` | `Faiaz#2026safe` | a friend request from Mim waiting |
| Tanvir Hasan | `tanvir` | `Tanvir#2026safe` | public photo posts, a chat with Nusrat |
| Sadia Mim | `mim` | `Mim#2026safe` | her request to Faiaz is still pending |

A good tour: sign in as Mim and open Faiaz's profile (his friends posts are
not there, and the page says why), then sign in as Faiaz, confirm Mim's
request, and sign in as Mim again.

### What you can do

- **Post** to *Friends*, *Public* or *Only me*, and change it later from the
  post's menu. The line under every post says in plain words who holds a key.
- **Comment and like.** Comments are encrypted with the post's own key.
- **Add friends**: send, confirm, decline and cancel requests; unfriend.
- **Chat** with anyone, one conversation per person.
- **Check a safety number** on any profile, to compare with that person
  somewhere that is not SafeBook.
- **Who holds a key**, on any post of yours, lists everyone holding a copy of
  its key and shows the stored ciphertext and its seal.
- **Settings and security**: edit your name and bio, see your encrypted email
  and phone, change your password, and read your sign in history.

### What it looks like

A social app first, so it looks like one: a white top bar with the search on
the left and Home, Friends, Chats and How it works as tabs in the middle; the
feed down the centre, shortcuts on the left, friend requests and contacts on
the right. Royal blue for anything you press. Mint is kept for one job: the
lock line under each post, and anything else that says who holds a key.
Avatars are initials in a colour worked out from the username. DM Sans
throughout, Roboto Mono only where bytes are shown as bytes. Light and dark,
and on a phone the tabs drop to a second row and a chat opens full screen.

### Small things that matter here

- **An eye on every password field**, and a **strength meter** on sign up that
  says how long the password would last against a thousand machines at
  SafeBook's scrypt setting. The password is the key, so it is worth saying.
- **Locks itself after 15 idle minutes.** While you are signed in your key is
  open in the session, so a tab left open on a shared computer is the weak
  point. The page signs out on its own and says why.
- **A post that is waiting for a key** shows up as a sealed card instead of
  silently missing, with the reason in one sentence.

---

## What is encrypted, and with which key

| key | protects | opened by |
|---|---|---|
| **your data key (DEK)** | email, phone, your RSA private key, your copy of every post key | your password through scrypt, or your recovery code |
| **your RSA key pair** | your copies of friends' post keys, chat session keys | the private half, which is sealed under your DEK |
| **the server KEK** | the key of each *public* post, and nothing else | the `.env` file |

### Every post has its own key

```
post text  --AES-256-GCM-->  ciphertext           (written once, never again)
    ^
 post key --wrapped with your DEK ----------->  key_owner            always
          --RSA-OAEP for each friend -------->  PostShare rows       Friends
          --wrapped with the server KEK ----->  key_public           Public
```

Changing the audience adds or deletes wrapped keys. The post itself is never
re-encrypted, and neither is anything else when you change your password,
which rewrites one envelope. There are tests for exactly that, because it is
the claim envelope encryption exists to make.

### Friends

A friend's copy of a post key is locked with their RSA public key, so only
their password opens it. The server stores every copy and can open none of
them.

Only the author can open their own post key, so only the author can make a
copy for a new friend. When a friendship is confirmed, the person confirming
hands over their friends posts on the spot; the other person's older posts
show as *waiting for a key* until that person next signs in, when
`catch_up()` makes the missing copies. That delay is the design showing
through, and the app says so rather than hide it.

Unfriending deletes every copy either of you handed the other. It cannot
un-read a post someone already opened while you were friends; it protects
what you post afterwards.

Comments are encrypted with the post's key, so exactly the people who can read
a post can read what was said under it.

### Chat

A fresh AES-256 session key per message, wrapped with RSA-OAEP twice: once
for the recipient, once for the sender, so both can scroll back. Each private
key is itself AES-GCM ciphertext under its owner's DEK.

### Integrity

Every post, comment and message carries an HMAC-SHA256 over a length-prefixed
encoding of its ciphertext and the ids it belongs to (the author; for a
comment also the post; for a message both people), keyed by an HKDF subkey of
the row key. GCM authenticates each field on its own; the row MAC is what
stops a comment being moved under another post or a row being re-homed onto
another user.

A row that fails either check is **not displayed**. Not displayed with a
warning next to it. A check whose failure still shows you the content is
decoration.

### What the server does see

Who is friends with whom, who liked what, when things were posted, who chats
with whom, and each person's name and bio. Those are what a social network is
made of, and hiding them needs a different design. The front page says so.

---

## Bugs found in the version I submitted

The original is the first commit in this repository. It was a private
notebook with a messenger rather than a social network; these were all
reproduced in it before they were fixed.

**The RSA layer bought nothing.** Every user's DEK was wrapped by the server
KEK, so the server could unwrap the DEK, decrypt the RSA private key with it,
unwrap the session key and read any message. `pwdwrap.py`, the scrypt module
meant to prevent exactly this, was in the repository and imported by nothing.
Wiring it up is most of what the first rewrite was.

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

## How it works, in the app

The app itself never lectures anyone. What a person sees is a line like
"Encrypted for you and 3 friends, each with a key of their own", and a small
question mark beside it. Clicking that opens one short explanation in plain
words, with a folded-away paragraph underneath for anyone who wants the real
names.

Behind those, `/lab/` is a set of five pages that run the experiment for one
claim each. They use throwaway keys made when the page loads, and none of
them touch a real account.

**Block modes.** The same drawn padlock through ECB, CBC and GCM, with
repeated 16 byte blocks counted under each. The plaintext has 544 and the ECB
ciphertext has 544 as well, which is why the padlock is still visible in it.
CBC and GCM have none.

**Nonce reuse.** Two messages under one key and one nonce. XOR the
ciphertexts and the keystream cancels; XOR in the message you already knew
and the other comes out exactly, with no attack on AES at all. The same pair
with a fresh nonce each time returns nothing.

**Timing.** Three ways of comparing a 32 byte MAC, timed live. A hand
written byte loop climbs from roughly 370 ns to roughly 1960 ns as more of
the guess is right, a 5x slope, and enough to find a MAC in 8192 tries
rather than 2^256. Each figure is the fastest of thirteen runs rather than
the average, because interference can only add time and averaging folds the
machine being busy into the answer.

The page also reports the honest negative result: `==` on `bytes` drops into
`memcmp`, shows no usable slope at this size, and stays flat. That is a
measurement failing to find something rather than proof it is safe, and the
page says so, which is why SafeBook uses `compare_digest` anyway.

**Password storage.** MD5, SHA-256, scrypt and Argon2id timed on the
machine running them, with the cost of walking every six letter lowercase
password at each speed. Minutes against hundreds of days.

**Tampering.** Flip any byte of a stored row and watch the row MAC and the
GCM tag both refuse it, with the untouched row verifying beside them.

---

## Layout

```
safebook/settings.py       no secrets; everything comes from the environment
secureapp/
  crypto.py                AES-256-GCM, and wrapping one key inside another
  pwdwrap.py               scrypt at N=2^16, password to wrapping key
  keys.py                  which key protects what
  keyring.py               sealing and opening posts, comments and messages,
                           handing out post keys, and the per-request Keyring
  friends.py               who is friends with whom
  mac.py                   HMAC-SHA256 with a per-table HKDF context
  rsa_utils.py             RSA-2048 keypairs and OAEP wrapping
  recovery.py              the one time recovery code
  session_keys.py          holding the DEK for one login, split in two
  auth_utils.py            constant time credential check, lockout
  models.py                Account, Post, PostShare, Comment, Like,
                           FriendRequest, Message, LoginAttempt
  views.py                 sign up, sign in, recovery, settings
  social.py                feed, posts, comments, likes, profiles, friends
  chat.py                  conversations
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

**121 tests, all passing**, grouped by what each one defends:

- `test_primitives.py` - AAD binding, fresh nonces, MAC domain separation,
  length prefix collisions, scrypt salting
- `test_auth.py` - the timing parity above, lockout, identical wording for
  real and invented usernames, POST only logout, the idle lock, and the demo
  cards appearing only where the demo accounts exist
- `test_confidentiality.py` - the server KEK refusing to open an only-me
  post, plaintext absent from the row, other people unable to open, publish,
  comment on, like or delete a post by its id
- `test_social.py` - a friend's copy of the key opening with their private key
  and nobody else getting one, a stranger unable to read or comment, new
  friends waiting for the author, unfriending taking the copies back,
  audience changes leaving the ciphertext alone, friend request rules, likes,
  and `next` never leading off the site
- `test_integrity.py` - a flipped byte or a wrecked MAC keeping a post, a
  comment or a message off the screen, a row re-homed onto another user or a
  comment moved under another post failing to verify
- `test_key_management.py` - a password change and a recovery both leaving
  every ciphertext byte untouched, a spent recovery code, KEK rotation and
  its dry run, and `new_keys --write` refusing to replace a real key
- `test_lab.py` - the numbers the lab pages print, asserted

`tools/browser_checks.py` (Playwright, using the Edge that comes with
Windows) opens every page signed out and signed in, in light and dark, and
fails on any status other than 200, any console error, any text below WCAG AA
contrast, or sideways scrolling at 390 px. It also signs in from a demo card,
tries the password eye, writes a post, likes it, comments on it, deletes it,
sends a chat message with Enter, and checks that signing out locks the
account. Run it against `runserver 127.0.0.1:8010` on a seeded database.

---

## Deploying

Any host that runs a Django app works; PythonAnywhere's free plan is enough.

1. Upload the project, make a virtualenv and `pip install -r requirements.txt`.
2. Copy `.env.example` to `.env`, run `python manage.py new_keys --write`, then
   set `DEBUG=False` and `ALLOWED_HOSTS=yourname.pythonanywhere.com`.
3. `python manage.py migrate`, `python manage.py seed_demo` if you want the
   demo people, and `python manage.py collectstatic`.
4. Point the web app at `safebook/wsgi.py`. WhiteNoise serves the stylesheet
   and script, so no static file mapping is needed.

With `DEBUG=False` the app turns on HTTPS redirects, secure cookies and HSTS.
Keep the `.env` out of the server's public folders: the KEK in it is what
opens the public posts.

---

## Known limits

- **This is not end to end encryption.** The server sees your plaintext while
  you are signed in, because it is a server rendered Django app and the
  decryption happens there. What it cannot do is read anything of yours while
  you are signed out. Real end to end would mean doing the crypto in the
  browser and never sending the key, which is a different application. The
  app's own wording ("SafeBook keeps no key of its own") is chosen to stay
  true to this.
- **A public post is readable by the server.** That is the deal you make by
  publishing it, and the composer says so when you pick Public.
- **The server knows the social graph.** Friendships, likes and who chats with
  whom are plain rows, because the server needs them to know whose keys to
  hand a post to.
- **Keys already handed out stay handed out.** Unfriending deletes the copies,
  but a friend who read a post before that may have kept what they read.
- **A new friend waits for the author** to sign in before older friends posts
  open for them. That is the cost of the server never holding those keys.
- **Upgrading from the notebook version drops old posts and messages.** Their
  seals covered title columns that no longer exist, and re-sealing needs keys
  only their authors' passwords open. See `migrations/0002_social_network.py`.
- **The recovery code is the whole account.** Anyone holding it can set a new
  password and open everything. It is shown once and never stored in a form
  that can be read back.
- **scrypt at N=2^16** costs about 280 ms per derivation on my laptop. That
  is deliberate: it is felt once at login, and multiplied by every guess an
  attacker makes.
- SQLite and the Django development server, neither of which belongs in
  production.
