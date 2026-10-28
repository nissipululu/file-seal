# Changelog

## 0.4.1

A small release on top of 0.4.0. A box that stops on Windows now starts again by itself, and the automated checks pass on Windows.

Windows

- A box that stops on Windows (a crash, or someone ending it) now starts again by itself. The Startup file runs a small supervisor that starts the box again after 10 seconds, then 20, 40 and so on up to 5 minutes if it keeps falling over, and writes each restart to the box log. Removing the login item, or running `uninstall`, stops the supervisor and the box together.
- The Startup file is written so that user names with accents, such as José, work.
- `uninstall` also stops the box of a login item that it only finds in the Startup folder.
- All the automated checks pass on Windows (358 of 358, and 377 on a Mac). The earlier failures were four wrong tests, not faults in the program: a file name Windows refuses, a hidden file rule, a file that cannot be replaced while it is open, and a difference in wording. One new check now judges partly downloaded files the same way on both systems.
- The Windows zip is now the same bytes every time it is built from the same source, like the two programs already were.

## 0.4.0 (first public release)

The tool existed as a private project before this. This is the first published version, after two rounds of code review. Here is what the review changed.

Security

- An arriving file is moved by a rename into a private folder, checked there, and that same file moves on to Verified or Rejected. A file can't change between the check and the move, and nothing is copied.
- Setup needs the company authority's fingerprint (`--pin-root`) and keeps it. Trusting whichever authority the share shows first is now a choice you have to make out loud (`--trust-on-first-use`).
- `authority approve` needs the department's key fingerprint (`--key`), so a request swapped in the share can't be approved by mistake.
- A certificate found in the share is installed only if the pinned authority issued it and it is for the right department and key.
- Trust files copied from the share are read once, size limited, link free, checked against the pin and the authority's signature, and written in one step. An older list never replaces a newer one.
- A failed publish to the share is an error now, not a silent success.
- A file name can no longer turn the Windows pop up message into code.
- Links and named pipes in the box folders are refused or given up on. One bad file can't stop a box or crash it in a loop.
- A pin that is empty or not a fingerprint is an error. A damaged memory of list numbers is kept aside and rebuilt instead of quietly switching the protection off.
- Crafted seals (dates out of range, very long chains, odd data) are refused and never crash the check. Weak keys are refused.
- Names with invisible letters or stacked marks are refused. Box folders are created readable by the owner only.
- The sealer reads the file once, writes through a short private temporary name, and applies the same field rules as the checker.
- The options that let a test pick the date can't be switched on from the environment any more.

Things you'll notice

- Setup and approve take the extra option described above. `authority share-setup` prints the exact setup command to hand to each department.
- Dates a person reads use the computer's own time zone ("Oct 26, 2026 8:05 PM local time"). Dates stored inside seals, lists and logs stay in UTC.
- A file that can't be confirmed (for example the company's list ran out) now stays in Incoming with a warning instead of moving to Rejected.
- Version 1 seals, from an early prototype, aren't accepted any more. They get a plain refusal.
- The tests don't touch your key store unless you add `--with-store`.

Building

- The SDK version is pinned, builds are repeatable, and warnings are errors. `package.sh` writes a `SHA256SUMS` file.
