# Security policy

## Reporting a problem

Please report security problems privately, not as a public issue.

The best way is GitHub's private reporting: open the Security tab of this repository and choose "Report a vulnerability". If that doesn't work for you, email hello@thesonset.com with "file seal security" in the subject, and keep exploit details out of public places until it's fixed.

Tell me what you did, what you expected, what happened, and the version (`sonsetseal version`). A short proof of concept helps a lot.

I'll answer within 7 days and tell you whether I can reproduce it. I'll keep you posted until it's fixed. After a fix is released you're welcome to publish your findings, and I'll credit you if you want me to.

## What counts

Anything that breaks a promise in the README. The serious ones:

- A forged, edited or withdrawn file passes the check.
- Someone who shouldn't be able to can read a key, or the authority's secret key.
- A crafted file, file name, folder or share makes the program run code, crash, hang, or lose a file.
- The check passes when something went wrong.

The limits in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) are known and aren't vulnerabilities on their own. A new way to exploit one of them is still worth a report.

## Which versions

The latest release. This is a young project run by one small company, so fixes go into the next release and older ones aren't patched.

## Checking what you download

Each release has a `SHA256SUMS` file listing the SHA 256 fingerprint of every file. Run `shasum -a 256 -c SHA256SUMS` (or `sha256sum -c SHA256SUMS`) in the folder you downloaded to. The downloads aren't code signed or notarized yet. If you build from source with the pinned SDK you get the same file byte for byte, so you can compare your own build with the release.

## What the project promises about itself

It has no outside packages, so there's no pile of other people's code to trust. It makes no network connections and sends no telemetry. Nobody but the company that runs it holds its keys.
