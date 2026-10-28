# Threat model

What the seal protects against, what it relies on, and where it stops. It's meant for people deciding whether to trust the tool, and for anyone reviewing the code.

## What it protects

That the file a person is about to open is the file one of their own company's departments sealed, unchanged, by a signer the company hasn't withdrawn.

## What it relies on

The company's authority. It's one small certificate authority run by the company's issuing department. Its secret key is a plain file in a folder only the owner can open (`authority/ca.key.pem`). Whoever holds that file can issue certificates as the company, so keep it on a computer you trust, off the share, and off backups you don't control.

The checking computer: the operating system, the user account and the folder with the trust files. Someone with administrator rights on the checking computer can change the answer. That's out of scope.

The pin, which is the fingerprint of the authority's certificate. The issuing department hands it to each computer. It is never taken from the share.

## Who the attacker is

Whoever sends the file. They can build any file they like: a forged, copied or half valid seal, odd file names, links and named pipes in a folder, oversized or malformed data.

Another user on the same computer, who may try to read what's sealed, drop files into a box or change settings.

An insider with write access to the company share. They can put anything there: a different authority, an old list of withdrawn certificates, a swapped request, a certificate for someone else.

A department that has lost its computer. That one is handled by withdrawing its certificate.

The program makes no network connections, so there is no network attacker.

## What the check does, in order

A file passes only if every step passes. The first failure ends the check, with a reason.

1. Read the end of the file: a marker, a length, and a block of at most 1 MiB. No marker means no seal. A length that doesn't fit means a damaged seal.
2. Parse the block. A field name repeated anywhere is refused. The format is exact, and unknown versions are refused.
3. Refuse a seal dated in the future, or from before this tool existed.
4. Check that the signing certificate is the one the signature names (a fingerprint inside the signed data).
5. Build the certificate chain to the company's root, as of the day the seal says it was made. Only the company's root is trusted, and nothing is fetched from the internet. A seal carrying more than 8 certificates is refused.
6. Check that the certificate may sign documents: not an authority, the right key usage, the right extended usage. A key that is too weak is refused (RSA under 2048 bits, an elliptic curve under 256 bits).
7. Check the company's list of withdrawn certificates. It must be signed by the authority, not older than one this computer has already seen, and not out of date. If it can't be confirmed, the file doesn't pass.
8. Verify the signature over the seal's signed data.
9. Apply the strict rules for the fields: only the known fields, the required ones present, no hidden or control characters, nothing over 300 characters.
10. Read the file once, hash it, and compare the hash and size with the seal. Then look at the end of the file again on the same open handle, to be sure it didn't change meanwhile.

Any unexpected error at any step is a refusal. It is never a pass and never a crash.

## What the folder boxes add

The Seal box and the Check box run as small background programs in the user's own session.

The file that is checked is the file that is kept. Cheap questions come first, asked of the file where it lies: is it still being written, does it open, does it carry a seal at all. A file with no seal is refused without being read further. A file that does carry one is moved by a rename into a private folder of the box that only the user can open, checked there, and that same file moves on to `Verified` or `Rejected`. A rename is instant however big the file is, keeps its dates and download marks, and takes exactly the file that was there. So someone who can write into `Incoming` can't change the bytes between the check and the move, and a newer file that arrives under the same name is judged on its own.

A file that can't be confirmed isn't thrown away. If the company's list has run out, or a file can't be read, the file goes back to `Incoming` with one warning, and it's looked at again only when it changes or the company's lists do. If the box is cut short while a file is in its private folder, the file is put back at the next pass.

Links and named pipes get special care. A link to a file is refused and moved aside as a link; what it points at is never read or moved. A link to a folder is never followed. A named pipe, which would wait for a writer forever, is given up on after five seconds. While that call is stuck the path is remembered, so it costs one waiting thread rather than one per pass, and it's tried afresh once the call ends. A file that was only slow isn't blacklisted.

Watched folders such as Downloads are judged in place, because a file there can't be taken away from its owner. A genuine file stays where it is. That verdict holds for the moment it was checked; a few seconds later the box checks the file again if it has changed, and it notices if the file was swapped for another during the check. If the folder is shared or synced with people you don't trust, drop files into `Incoming` and open them from `Verified` instead. A name that says "still downloading" (`.part`, `~`, a leading dot) is believed only while the file is still changing. After ten minutes it's judged like any other file, so a tampered sealed file can't hide behind such a name.

One bad file can't stop the box. A file that can't be read, moved or checked is reported once and tried again. An unexpected error is logged and the box carries on, so a login item that restarts a crashed program doesn't meet the same file again and again.

Everything a person reads goes through a filter that shows control, hidden and direction changing characters as visible escapes. A note about a file with a very long name still gets written.

For the pop up message, the text is quoted for AppleScript on a Mac. On Windows the message travels in the environment of the PowerShell process and the script is fixed text, so a file name can't become code.

The box folders are created readable by the owner only. On Windows a box folder has to be inside the user's own profile, whose default permissions already keep other users out.

## What the share adds

The company share is a convenience. It is not a source of trust.

Every file read from the share is a small ordinary file: no links, no pipes, nothing over 1 MiB, and an open that doesn't answer in time is given up on.

The authority on the share must match a pin the computer was given, or nothing is copied. A new authority is never adopted on its own unless you ran setup with `--trust-on-first-use`.

The list of withdrawn certificates from the share has to be signed by that authority and not be older than the one already held, and only then does it replace the local copy. Each file is read once and the bytes that were checked are the bytes that get written.

A certificate that turns up in the share is installed only if the pinned authority issued it, it's for this department's name and key, and the chain is valid.

Approval is tied to the key as well as the name. `authority approve` needs the key fingerprint that the department's own setup printed and told the issuing department. A request swapped in the share for one holding someone else's key is refused.

Writes into the share replace the file in one step, even if a link was planted there, and nothing the link points at is written. A withdrawal that couldn't be written to the share is reported as a failure. If a share write fails during approval, approving again puts the issued certificate there.

Departments need to write only into `Requests`. Make `Trust` and `Certificates` writable by the issuing department alone. Anyone who can write to `Trust` can delete a list or put back an older one, and hold a withdrawal back for as long as the old list is still valid. The checking computers tell the person when the company's trust can't be read or updated, but they can't know a newer list exists if it never reaches the share.

## Known limits

A department can choose the date in its seals. The department that holds the key writes the date. A later version could add a countersigned time from the authority.

With Mode B, a company's existing Microsoft AD CS, any certificate the company's authority issues for signing documents can seal as itself. Restrict who can enroll for that template.

Seals don't survive a rewrite. Re encoding a picture or re saving a document drops trailing data. The result is an unsealed file, and the check says so.

The authority's secret key is a plain owner only file. It isn't protected by a passphrase, so protect the computer it sits on.

A new checking computer has no memory of older lists. The protection against putting back an older list of withdrawn certificates starts from the first list a computer sees.

Windows is less tested than the Mac. This release ran the whole flow on Windows 11 for Arm in a virtual machine, and all the automated checks pass there, but it has not been tried on a physical Windows computer. A box that stops on Windows is started again by a small supervisor that the Startup file runs. If someone ends the supervisor itself by hand, the box keeps running but is not restarted until the next sign in. The program is not signed, so Windows may warn about an unknown publisher until IT allows it by its fingerprint.

Releases aren't code signed or notarized yet. Check them against `SHA256SUMS`, or build from source.

Checks use the computer's clock. Someone who can set the clock back on a checking computer can make an old list look current. That takes administrator rights, which are out of scope.

## Reviews so far

The code went through two rounds of line by line review before this release, and the automated attack checks in `SonsetSeal.Tests` cover every hole that was found. It has not had a professional third party security audit, and it shouldn't be treated as if it had. If you find something, please report it as described in [SECURITY.md](../SECURITY.md).
