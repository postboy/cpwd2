## cpwd 2.0 — tiny and handy password manager

cpwd is simple, stateless password manager. You enter a master key and the name of an account (ex. "gmail"), wait a few seconds, and cpwd generates a password for that account ready in your clipboard. You can reuse the same master key for all your accounts, and cpwd will generate a different strong password for every account. Every time you want to log in, just launch cpwd and enter the same master key and account name. Simple! Useful!

cpwd is a C port of [npwd] (https://github.com/kaepora/npwd) by [Nadim Kobeissi] (https://nadim.computer), **but from version 2.0 it's not compatible with original**. If you need a version comapitble with npwd, look at [cpwd] (https://github.com/postboy/cpwd)!

### Benefits
1. Memorize a single master key, but still get a different strong password for every account.
2. Quick and easy command-line access.
3. Copies password straight to clipboard then clears clipboard automatically in 15 seconds.
4. Doesn't store anything: no password databases to manage.

### Usage
1. Run `cpwd ([-r] [-m]) [%account_name%]`, ex. `cpwd`, `cpwd twitter`, `cpwd -r`, `cpwd -r reddit`. Adding `-r` allows you to run cpwd in registration mode where you need to enter master key twice to avoid errors. It's very useful when you're registering or changing password somewhere. Adding `-m` allows you to run cpwd in migration mode where you first get npwd-copatible password and then a new, cpwd2 password from the same master key and for same account name. This mode was made specially for migration from npwd and old versions of cpwd. Adding `%account_name%` allows you to skip entering account name in dialog mode.
2. Enter your master key (hidden, same for all accounts).
3. In a few seconds, your password for that account is in your clipboard. Clipboard is cleared automatically after 15 seconds for security.

### Notes
1. **Weak master key ruins everything**. Your master key should have at least 8 characters, contain lowercase and uppercase letters, numbers and special symbols.
2. cpwd offers essentially the same functional as npwd plus some new. cpwd allows you to get maximum speed of work while npwd is much easier to install. cpwd is written in C while npwd is written in JavaScript, thus depends on `Node.JS` and `npm`.
3. Key derivation is done with [scrypt] (https://www.tarsnap.com/scrypt.html), account name acts as salt. Parameters: N = 2<sup>17</sup> = 131072, r = 8, p = 1, L = 16. Binary data is encoded using modified ASCII85 algorithm, so generated passwords contain 20 symbols from uppercase and lowercase English letters, numbers and special symbols sets.
4. Account names are lowercased automatically for usability. "GitHub" == "github".

### Platforms
* Linux (tested)
* Mac OS X, OpenBSD and other UNIXes (not tested, but probably supported)
* Windows and other OSes (you may need to do some porting work)

### Installation
1. `git clone https://github.com/postboy/cpwd2.git` to download repository.
2. Build cpwd. On *nix systems with GCC you can do it via running `build.sh` script.
3. Linux/OpenBSD only: install `xclip` package for working with clipboard (you can use `xsel` package aswell, just edit the main.c for a bit).

### Tips on cpwd launching speed-up
1. On *nix: add a lines `alias p='/path/to/./cpwd2'`, `alias r='/path/to/./cpwd2 -r'` and `alias m='/path/to/./cpwd2 -m'` in your `.bashrc` file for adding three commands to your shell: `p` that launches cpwd in normal mode, `r` that launches cpwd in registration mode and `m` that launches cpwd in migration mode.
2. On Windows: for faster launching cpwd via `p`, `r` and `m` commands in cmd you can create three batch scripts in some directory that's shown as result of `path` command in cmd: `p.bat` containing a line `@echo off && call "C:\path\to\cpwd.exe"`, `r.bat` containing a line `@echo off && call "C:\path\to\cpwd.exe -r"` and `m.bat` containing a line `@echo off && call "C:\path\to\cpwd.exe -m"`.

### Tips on cpwd computing speed-up
1. Check if your processor supports SSE (on *nix just run `grep sse /proc/cpuinfo` to do it). If it does, compile against crypto_scrypt-sse.c instead of crypto_scrypt-nosse.c (and if you use GCC, add a flag `-march=native`).
2. Enable optimization in your compiler. If you use GCC, you can do it with flags `-march=native` (compile just for current processor) plus `-O1` (recommended) or `-O2` or `-O3` (not recommended). Test them all and use the best for you.

### See also
1. [cpwd version 1] (https://github.com/postboy/cpwd).
2. My posts in Russian about [first] (https://medium.com/@posthedgehog/%D0%BA%D0%B0%D0%BA-%D1%8F-%D1%81%D0%B4%D0%B5%D0%BB%D0%B0%D0%BB-%D1%81%D0%B5%D0%B1%D0%B5-%D0%BC%D0%B5%D0%BD%D0%B5%D0%B4%D0%B6%D0%B5%D1%80-%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D0%B5%D0%B9-4b4404352bd0) and [second] (https://medium.com/@posthedgehog/what-do-you-represent-de947f7c008a) versions of this project.
3. [npwd] (https://github.com/kaepora/npwd) — imagine cpwd with very easy installation, but maybe not that fast work :) cpwd version compatible with npwd is [here] (https://github.com/postboy/cpwd).
4. [jkalbhenn's password manager] (https://github.com/jkalbhenn/scrypt) is essentialy the same project, but started more than two years before this.
5. [kyle] (https://github.com/esurharun/kyle) is a similar project, but started about 1.5 years before this.

### Related work
1. [Password Multiplier] (https://www.cs.princeton.edu/~jhalderm/projects/password) using iterated hashing, 2005.
2. [PwdHash] (https://www.pwdhash.com) using hashing and is [much less secure] (https://security.stackexchange.com/questions/52355/how-secure-is-the-pwdhash-algorithm-and-system), 2005.
3. [Usability study and critique of PwdHash and Password Multiplier] (http://people.scs.carleton.ca/~paulv/papers/usenix06.pdf).
4. [Janus Personalized Web Anonymizer] (http://theory.stanford.edu/~matias/papers/fc97.pdf), 1997, and it's successor, [Lucent Personalized Web Assistant] (http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.145.7899&rep=rep1&type=pdf), 1998, both using hashing, are early examples of such password manager.
5. [Password manager without a password manager] (https://gist.github.com/jaseg/3334991) that [was broken] (https://news.ycombinator.com/item?id=4374888), 2012.

### License
cpwd itself is licensed under [GPL v3] (https://www.gnu.org/licenses/gpl-3.0.en.html), but uses [scrypt 1.1.6] (https://www.tarsnap.com/scrypt.html) licensed under [BSD 2-Clause] (http://opensource.org/licenses/bsd-license.php), [btoa 4.0] (http://www.ibiblio.org/pub/packages/ccic/software/unix/utils/btoa.c) and [GCC Poison] (http://blog.leafsr.com/2013/12/02/gcc-poison) which is public domain. Commands for working with clipboard are taken from [node-copy-paste] (https://github.com/xavi-/node-copy-paste).

### Author
Zuboff Ivan // anotherdiskmag on gooooooogle mail
