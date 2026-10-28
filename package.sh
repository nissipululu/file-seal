#!/bin/bash
# Builds what a client's IT department needs, with nothing to buy: the Mac program, a Mac installer package,
# the Windows program in a zip, the fingerprints IT puts on its allow list, and a plain note for IT.
# Usage: bash package.sh OUTPUT_FOLDER [VERSION]
# Nothing here is signed. Signing and notarization are the paid steps.
# Two builds of the same source give the same program, byte for byte (see Directory.Build.props).
set -euo pipefail
OUT="${1:?Give an output folder, for example: bash package.sh ~/Desktop/release}"
VERSION="${2:-$(sed -n 's|.*<Version>\(.*\)</Version>.*|\1|p' "$(dirname "$0")/Directory.Build.props")}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DOTNET="${DOTNET:-$(command -v dotnet || echo "$HOME/.dotnet/dotnet")}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
mkdir -p "$OUT"

for rid in osx-arm64 win-x64; do
  "$DOTNET" publish "$HERE/SonsetSeal.Cli" -c Release -r "$rid" --self-contained true \
    -p:PublishSingleFile=true -p:Version="$VERSION" -o "$OUT/$rid" > /dev/null
done

# Mac installer package: puts the program in /usr/local/bin. IT pushes it with Jamf or an Intune unmanaged PKG.
rm -rf "$OUT/pkgroot" && mkdir -p "$OUT/pkgroot/usr/local/bin"
cp "$OUT/osx-arm64/sonsetseal" "$OUT/pkgroot/usr/local/bin/sonsetseal"
chmod 755 "$OUT/pkgroot/usr/local/bin/sonsetseal"
xattr -cr "$OUT/pkgroot" 2>/dev/null || true
pkgbuild --root "$OUT/pkgroot" --identifier ca.sonset.sealtool --version "$VERSION" --install-location / \
  "$OUT/SonsetSeal-$VERSION-mac.pkg" > /dev/null 2> >(grep -v 'write: Permission denied' >&2)
# (On this Mac pkgbuild prints 'write: Permission denied' and adds harmless ._ attribute files, because macOS marks every
#  file made by a tracked process with a protected attribute. The package is fine; it is only untidy.)

# Windows: the program in a zip. No installer script on purpose, many companies run scripts in a restricted mode.
rm -f "$OUT/SonsetSeal-$VERSION-windows-x64.zip"
( cd "$OUT/win-x64" && zip -q "../SonsetSeal-$VERSION-windows-x64.zip" sonsetseal.exe )

MAC_HASH="$(shasum -a 256 "$OUT/osx-arm64/sonsetseal" | cut -d' ' -f1)"
WIN_HASH="$(shasum -a 256 "$OUT/win-x64/sonsetseal.exe" | cut -d' ' -f1)"
PKG_HASH="$(shasum -a 256 "$OUT/SonsetSeal-$VERSION-mac.pkg" | cut -d' ' -f1)"
ZIP_HASH="$(shasum -a 256 "$OUT/SonsetSeal-$VERSION-windows-x64.zip" | cut -d' ' -f1)"

cat > "$OUT/FOR IT.txt" <<EOF
Sonset file seal $VERSION: note for the IT department

WHAT IT IS
One small program with no installer service and no account. It lets a company seal files with its own certificate
authority and check the seal before a file is opened. If you use the automatic folders (below), it runs two small
background programs in the user's own login session, one for the Seal box and one for the Check box, started by a login item.
It holds no data of ours. Sonset runs nothing for you and keeps no keys, certificates or files.

WHAT IT DOES ON THE NETWORK
Nothing, in the standard setup (the company's own trust folder on disk). In the Microsoft AD CS setup it asks the
company's own certificate revocation list for the signer's certificate, and only after the chain has been proven to end at
the company's own root. It sends no usage data, no telemetry and nothing to Sonset.

WHAT YOU PROVIDE
- An issuing department inside the company runs the authority (authority init, authority sign, authority revoke).
- The trust folder the authority publishes goes to every checking computer.

FILES AND FINGERPRINTS (SHA 256). Put the program's fingerprint on your allow list if you use hash rules.
  Mac program          sonsetseal                              $MAC_HASH
  Mac package          SonsetSeal-$VERSION-mac.pkg            $PKG_HASH
  Windows program      sonsetseal.exe                          $WIN_HASH
  Windows zip          SonsetSeal-$VERSION-windows-x64.zip    $ZIP_HASH
Every release has its own fingerprints. SHA256SUMS next to this note lists the fingerprint of every file in the release, in the
format "shasum -a 256 -c SHA256SUMS" (or "sha256sum -c") checks.

SIGNING STATUS
These files are NOT signed or notarized yet. If your policy requires a signature, tell Sonset which kind you need.
Options that need no purchase by you: allow the file by its fingerprint, or sign it with your own internal code signing certificate.

MAC
- Push SonsetSeal-$VERSION-mac.pkg with a Jamf policy, or as an Intune unmanaged PKG. It installs /usr/local/bin/sonsetseal.
- Apple silicon only in this build.

WINDOWS
- Copy sonsetseal.exe from the zip to a folder such as C:\\Program Files\\Sonset (a Win32 app deployment through Intune works with any setup file and a silent command).
- Windows 64 bit (x64). It also runs on Windows on ARM through Microsoft's emulation.

SET UP A DEPARTMENT COMPUTER (one command, nothing to do afterwards)
  sonsetseal setup --share "<company share folder>" --department "<department name>" --made-for "<team>" --pin-root <authority fingerprint>
The issuing department gives each department this whole command. The authority fingerprint (--pin-root) is printed when the
issuing department runs "authority share-setup". It makes the computer trust only the company's own authority, even though
everyone who can write into the share could put another one there. Setup prints a key fingerprint for the department.
It makes the department's key in the computer's own protected store, leaves a request in the company share, creates the
Seal box and Check box folders (in a folder called Sonset in the user's home folder) and starts both boxes at every login.
The department tells the issuing department that key fingerprint (in person or by phone, not through the share). The issuing
department then approves with one command: sonsetseal authority approve --name "<department name>" --key "<key fingerprint>"
The department's computer installs its certificate by itself and starts sealing.

WHICH FOLDERS THE CHECK BOX WATCHES
Besides its own Incoming folder, the check box watches the user's Downloads folder. Add --no-downloads to setup to leave
that out. Add other folders with --also-watch, as many times as you like, for example:
  --also-watch "<a synced SharePoint or OneDrive folder>"
  --also-watch "<a shared drive folder>"
Each folder must exist when you run setup. Run setup again to change the list.
A file in a watched folder that carries a seal is checked. A genuine one stays where it is and the user gets one short
message. A file that fails moves to the Rejected folder in the Check box with a note that says why, and the user gets a
message. A file that cannot be confirmed (the company's withdrawn list ran out, say) or cannot be read stays where it is
and the user gets one warning about it. A file with no seal is left alone: it is not moved, not named in a message and
not read beyond its last few bytes. Partly downloaded files wait until they are finished. Hidden files and links are skipped.
An email attachment is checked only once it has been saved into a watched folder (Downloads, for most mail programs).
The box never opens anyone's mailbox.
In a shared or synced folder, a failing file moves out for everyone who shares that folder. On Windows, files that OneDrive or SharePoint
has not downloaded to the computer yet are skipped until they are on it. Watching a very large folder is fine: a file
that has not changed is not read again, and the watched folders are looked at every ten seconds.
When IT publishes a new list of withdrawn certificates, files already judged are looked at again, so a withdrawal
reaches files that were fine when they arrived.

MESSAGES ON THE SCREEN
One short message for each batch of files, never one per file. Choose with --notify on setup: all (the default),
problems (only what needs a look) or off. Each box keeps its own choice. To see that messages arrive, run:
  sonsetseal notify-test
On a Mac the message is shown under the name Script Editor, so notifications for Script Editor must be allowed
(System Settings, Notifications, Script Editor) and Focus must be off.

LOGIN ITEMS (setup does this for you; this is only if you want to manage them by hand)
  sonsetseal seal-box autostart --folder "<seal box folder>" --install
  sonsetseal check-box autostart --folder "<check box folder>" --install
  (add --remove instead of --install to stop a box and take its login item away)
--install writes the login item and starts the box now. It is one small file in the user's own LaunchAgents folder on a
Mac, or in the user's Startup folder on Windows. Each login item has its own name, made from the box folder's full
path, so several boxes on one computer never clash. A box starts again by itself if it ever stops, and only one copy
of a box runs at a time.

REMOVE IT
  sonsetseal uninstall
This stops both boxes, removes their login items and removes the department's key from the computer's protected
store. Every file in the box folders and in the watched folders stays exactly where it is. Then delete the program
file, and the folder .sonsetseal in the user's home folder if you want the settings gone too.
EOF

# One checksum file in the standard format, covering every file in the release, so a download can be verified with one command.
# The two programs are also released on their own, so the fingerprints in the IT note can be checked against files you can download.
cp "$OUT/osx-arm64/sonsetseal" "$OUT/sonsetseal-$VERSION-macos-arm64"
cp "$OUT/win-x64/sonsetseal.exe" "$OUT/sonsetseal-$VERSION-windows-x64.exe"
( cd "$OUT" && shasum -a 256 "SonsetSeal-$VERSION-mac.pkg" "SonsetSeal-$VERSION-windows-x64.zip" "sonsetseal-$VERSION-macos-arm64" "sonsetseal-$VERSION-windows-x64.exe" "FOR IT.txt" > SHA256SUMS )
printf 'SHA256 fingerprints\nmac program   %s\nmac package   %s\nwin program   %s\nwin zip       %s\n' "$MAC_HASH" "$PKG_HASH" "$WIN_HASH" "$ZIP_HASH" > "$OUT/SHA256.txt"
echo "Built in $OUT:"
ls -la "$OUT" | grep -E "pkg|zip|IT|SHA" | awk '{print "  " $5 "  " $9 " " $10 " " $11}'
