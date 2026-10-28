# Sonset file seal

Seal a file with your company's own certificate authority, and check the seal before you open it.

It adds a signed seal to the end of a file. The seal says who made the file, who it is for and what it is, and it locks in the file's exact contents. Before anyone opens the file, a check confirms that the seal came from your company's own authority, that the company hasn't withdrawn it, and that the file hasn't changed since it was sealed. If something is wrong, the check says so and the file stays closed.

It runs on your own computers. There is no account, no server, no network use and no telemetry.

## Why I made it

It takes seconds now to make a convincing picture, document or recording, and a real one can be changed without leaving a trace. A company that receives a file still has to decide whether to trust it. Usually that means looking at who sent it, and that stops working the moment the sender's account is faked or taken over.

I wanted a company to be able to seal its own files and check the seal before opening one, using only what it controls: its own certificate authority and its own keys, with no outside service in the middle. Whoever wrote the software holds no keys and sees none of your files.

I'm publishing it as free software so anyone can read the code, test the claims and run it themselves. It is early. Its limits are written down in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), and I'd rather you find the holes than someone else.

## What a pass means

When the check says VERIFIED:

- The file ends with a seal made by a certificate that your company's authority issued.
- That certificate was valid on the day the seal says the file was sealed, and it may sign documents.
- The company hasn't withdrawn the certificate, and its list of withdrawn certificates is up to date.
- The file is, byte for byte, what was sealed.
- The fields in the seal (Made by, Made for, What it is, and the optional ones) are exactly what the department signed.

Anything else is refused with a reason: no seal, a damaged seal, an edited file, a signer your company doesn't recognise, a signer it has withdrawn, or a list that is too old to rely on.

## What it doesn't do

- It doesn't hide or encrypt anything.
- A seal doesn't survive anything that rewrites the file. Save it again in another program, or upload it to a site that re encodes pictures, and the seal is gone. The check says so.
- A department that holds its key can choose the date it writes into a seal.
- It can't tell you whether the contents are true. It tells you who vouched for them and that they haven't changed.

## Status

Version 0.4.0, the first public release.

| Part | State |
| --- | --- |
| Sealing, checking, the company authority, withdrawing a department | Works. The automated checks in this repository cover it. |
| macOS on Apple silicon, with the Keychain and login items | Tried by hand on a real Mac from start to finish. |
| Windows | This release ran the whole flow on Windows 11 for Arm in a virtual machine (the x64 program under emulation): key in the Windows certificate store (it can't be exported), start at sign in, sealing, checking, the Downloads watch, the on screen message, withdrawing and removal. All the automated checks, including the key store ones, pass there. A box that stops (a crash, or someone ending it) is started again by itself by a small supervisor that the Startup file runs. Not tried on a physical Windows computer. The program isn't signed. Windows Defender raised nothing in the lab and no SmartScreen warning appeared, but that was a virtual machine, so a real PC may warn about an unknown publisher until IT allows the file by its fingerprint. |
| Linux | The library builds. There is no protected key store or login item for Linux, so use `--key-file`. |
| A company that already runs Microsoft AD CS (`seal --store-cert`, `check --system`) | Written, not tried against a real AD CS. |
| Signed downloads | Not yet. The release files are unsigned. Check them against `SHA256SUMS`. |

I tested sealing and checking with text and PDF files. Other file types should work, since most programs stop reading where the real content ends, but I haven't tried every format.

## Try it in five minutes

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download). This trial keeps everything in the current folder: no login items, nothing in your Keychain, nothing sent anywhere.

```bash
git clone https://github.com/nissipululu/file-seal.git
cd file-seal
dotnet build SonsetSeal.Cli -c Release -o out
alias sonsetseal='dotnet out/sonsetseal.dll'

echo "Q3 report. Not for sharing." > report.txt

# 1. The company's IT department makes the authority.
sonsetseal authority init --company "Example Co" --department "IT" --home ./it

# 2. A department makes its own key and a request. The key never leaves this machine.
# It prints a key fingerprint. The department tells IT that fingerprint, in person or by phone.
sonsetseal department request --name "Marketing" --key-file --home ./marketing

# 3. IT signs the request. IT types the department's name again so a look alike name can't slip through,
# and the key fingerprint the department gave, so a request swapped in on the way can't be signed by mistake.
sonsetseal authority sign --request ./marketing/departments/marketing/request.csr.pem --name "Marketing" --key "XXXX XXXX XXXX XXXX" --home ./it

# 4. The department installs the certificate that came back, and seals a file.
sonsetseal department install --cert ./it/authority/issued/marketing-*.pem --home ./marketing
sonsetseal seal report.txt --made-by "Jo Smith" --made-for "Leasing team" --what "Q3 report" --home ./marketing

# 5. Anyone with the company's trust folder can check it.
sonsetseal check report.sealed.txt --trust ./it/trust --home ./reader
```

Put the fingerprint that step 2 printed where the X's are. Then change one byte of `report.sealed.txt` and run the check again: it answers `DO NOT OPEN ... The file was changed after it was sealed.` Withdraw the department with `sonsetseal authority revoke --name "Marketing" --reason "laptop lost" --home ./it` and the original file is refused too, with the reason and the date.

Exit codes: 0 when everything passed, 1 when something was refused, 2 when the command itself failed. A failure never looks like a pass.

## Use it in a company

The authority and the trust folder stay with the issuing department (IT). Departments never send a key anywhere. They send a request, and a certificate comes back.

1. IT runs `authority init --company "Example Property Group" --department "IT Department"` once, then `authority share-setup --share "<company share folder>"`. The share setup prints the authority's fingerprint and the exact setup command to give each department. Keep the authority folder, which holds the secret key, off the share.
2. Each department runs one command. IT hands it over with the fingerprint already in it: `setup --share "<company share folder>" --department "Marketing Department" --made-for "Leasing team" --pin-root <fingerprint>`. It makes the department's key in the computer's protected store (the Mac Keychain or the Windows user certificate store), leaves a request in the share, creates the Seal box and Check box folders and starts both at every login. It prints a key fingerprint, which the department tells IT in person or by phone, not through the share.
3. IT approves with `authority approve --name "Marketing Department" --key "<key fingerprint>"`. The department's computer installs its certificate by itself.
4. From then on nobody types anything. Files saved into `Seal box/Drop here` are sealed into `Sealed`. Files that arrive in `Check box/Incoming` land in `Verified`, or in `Rejected` with a note saying why. The Check box also watches the Downloads folder and any folder you add with `--also-watch`, and checks any file there that carries a seal.
5. When a computer is lost, IT runs `authority revoke --name "Marketing Department" --reason "laptop lost"`. The new list reaches every checking computer through the share.

The pin in step 2 matters. Everyone who can write into the share could put another authority there, and the pin is what makes a department trust only yours. For a trial on your own you can use `--trust-on-first-use` instead, which trusts whichever authority the share shows first.

`sonsetseal uninstall` stops both boxes, removes their login items and removes the department's key from the computer. Every file in the box folders stays where it is. Run `sonsetseal` with no arguments for the full list of commands.

## Build and test

```bash
dotnet build -c Release
dotnet run --project SonsetSeal.Tests -c Release            # runs in a temporary folder, no key store
dotnet run --project SonsetSeal.Tests -c Release -- --with-store   # also runs the tests that make a key in your Keychain, then remove it
bash package.sh ./release                                   # Mac program and installer package, Windows zip, SHA256SUMS
```

There are no outside packages. The program uses only what ships with .NET, so there is nothing else to download, audit or keep up to date. The SDK version is pinned in `global.json`, and two builds from the same source give the same file byte for byte.

## Reporting a problem

Please report security problems privately, as described in [SECURITY.md](SECURITY.md). Anything else is welcome as an issue or a pull request; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Free to use, change and share, at your own risk, with no warranty.
