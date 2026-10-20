# Contributing to Covee

Thank you for helping. Bug reports, fixes and improvements to the docs are all welcome.

## Before you start

- **Bugs**: open an issue with what you did, what you expected and what happened, and the output of `covee version` and `covee status <network>` (remove anything private).
- **Larger changes**: open an issue first to agree on the approach.
- **Security problems**: report them privately; see [SECURITY.md](SECURITY.md).

## Building and testing

You need Go 1.26 (with Go's default `GOTOOLCHAIN=auto`, the exact version each module asks for downloads itself), Python 3.10 or later, Node.js 20 or later for the console's tests and, for the server images, Docker. The Mac and iPhone apps need Xcode and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

```sh
python3 -m unittest discover -s tests          # deployment and release tools
go test ./...                                   # server services
(cd cli && go test ./...)                        # the covee command
(cd native/engine && go test ./...)              # the apps' packet engine
(cd deploy/gateway && go test ./...)             # the gateway device
(cd deploy/console-node && go test ./...)        # the console's network device
node --test internal/console/frontend.test.cjs   # the admin console
python3 scripts/apple.py test --platform macos   # the apps (macOS, Xcode)
python3 scripts/build_cli.py                     # build covee for this computer
```

Every change needs tests that would fail without it. Keep messages people see plain and specific: say what happened and what to do.

## Pull requests

- Keep each pull request to one change, with a description of what and why.
- Run the tests above that cover what you changed.
- Never commit secrets, real addresses, account IDs or other personal data, including in tests: use `example.com`, `192.0.2.x` and placeholder IDs.

## License

Covee is licensed under the [Apache License 2.0](LICENSE). By contributing, you agree that your contribution is licensed under it as well (section 5 of the license).
