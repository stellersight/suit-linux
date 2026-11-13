# Governance

SUIT for Linux is developed and maintained by StellerSight Private Limited,
which owns the project, its repositories, its signing keys and its release
decisions.

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| Lead maintainer | Vinod Padayachi (StellerSight) | Sets direction and the roadmap, reviews and merges changes, cuts and signs releases, handles security reports. |
| Maintainer | Open | Reviews and merges changes, triages issues, may cut releases. Granted to a sustained contributor by the lead maintainer. |
| Contributor | Anyone | Proposes changes through pull requests under the [contribution rules](CONTRIBUTING.md). |

## Decisions

Changes are proposed as pull requests. A maintainer merges a change once
tests pass and the change keeps the documented guarantees, or documents a new
limit. Changes to the security model, the policy formats or the audit format
(`suit.audit.v1`) are discussed in an issue first, and recorded in the README
and the conformance matrix.

## Continuity

The project must be able to keep accepting changes, handling security reports
and releasing if any one person becomes unavailable.

- Done: release, packaging and repository-signing steps are scripted and
  documented (`packaging/`, and the `packages` repository's `release.sh`).
- In progress: a second owner of the GitHub organisation `stellersight`, and an
  offline backup of the package-signing keys that a second, named StellerSight
  officer can access. Until both are in place the project has a bus factor of
  one, and says so.

## Code of conduct

Participants follow the [Code of Conduct](CODE_OF_CONDUCT.md).
