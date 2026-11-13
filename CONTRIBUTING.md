# Contributing

Thank you for helping. SUIT for Linux runs as root, so every change is judged
first by what it does to the trust boundary.

## Before you start

- Security problems go to security@stellersight.com, never to a public issue
  (see [SECURITY.md](SECURITY.md)).
- For a change to the security model, policy formats or the audit format,
  open an issue first.
- Small fixes and tests can go straight to a pull request.

## Requirements for a change

- **Tests.** New behaviour comes with unit tests in `tests/`. A change to the
  broker, policy loading or the grant lifecycle also needs an end-to-end check
  in `tests/e2e/run.sh` where one is possible.
- **Fail closed.** Anything the broker cannot verify is refused, never assumed.
- **Standard library only.** No runtime dependencies beyond Python 3.8+.
- **Documentation.** If a guarantee or limit changes, update the README's
  "Guarantees and their limits" table in the same pull request.
- **Style.** Follow the existing code: type hints, short functions, docstrings
  that say why. Run `python -m unittest discover -s tests` before pushing.

## Sign your work (DCO)

Every commit must carry a `Signed-off-by` line, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or otherwise have the right to submit it under the
project's licence (Apache-2.0).

```bash
git commit -s
```

## Review

A maintainer reviews every pull request. The aim is for changes to be reviewed
by someone other than their author before release.
