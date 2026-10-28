# Contributing

Thanks for looking. People will lean on this tool to decide whether to open a file, so changes should be small, clear and tested.

## Build and test

```bash
dotnet build -c Release
dotnet run --project SonsetSeal.Tests -c Release
```

The tests are a console program, so there's no test framework to download. Each check prints PASS or FAIL, and the program exits with a non zero code if any failed. Everything runs in a temporary folder. Add `-- --with-store` to also run the tests that make a department key in your Keychain or Windows certificate store; they remove the key again. After a run with the store, check that nothing was left behind (on a Mac, `security find-identity login.keychain-db | grep -ci Sonset` should print 0).

Set `SONSETSEAL_NOTIFY=off` so the tests don't pop up messages.

## Ground rules

No outside packages, not even for tests. Everything uses what ships with .NET. That keeps the list of code to trust short.

A security fix or a new check comes with a test that fails without it. If someone found a hole, the test is their repro.

A failure must never look like a pass. When something unexpected happens, refuse and say why.

Treat anything a file, a file name or a shared folder can influence as untrusted. Don't build commands or scripts out of it, and print it only through `Display.Safe`.

Messages people read should be short and in everyday words: no jargon, no stack traces, and a hint about what to do next.

Keep the order of the checks in `Checker.cs`. It's deliberate. An untrusted chain, for example, is reported before anything else about the file. Read the comments before moving things.

Match the code around yours: names, comment density and style.

## Pull requests

Say what you changed and why in a few sentences, and which tests cover it. Small pull requests get reviewed faster. If your change touches the check, the trust files, the folder boxes or the key store, say so at the top.

## Security problems

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
