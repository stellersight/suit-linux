# Roadmap, November 2026 – November 2027

SUIT for Linux is a local, daemonless broker for approved privileged
commands. It is not a bastion, a session recorder or a credential vault, and
this roadmap does not try to make it one. The aim for the year is evidence
that it works, not feature parity with larger platforms.

## Next three months

- **Supported-platform commitment.** A named Tier 1 list, with install,
  upgrade, removal, SELinux and AppArmor enforcing, and signature checks
  automated in CI for each.
- **Release provenance.** Signed GitHub artifact attestations for every
  package; reproducible package builds demonstrated.
- **Coverage.** Measured statement and branch coverage, published per release.

## Three to six months

- **Independent pilots.** At least two deployments run by organisations other
  than StellerSight, with a published, anonymised report of what failed.
- **Independent security assessment** of the root boundary, with scope,
  findings and fixes published.
- **Separation of duties** between actions, enforced at request, approval and
  execution.

## Six to twelve months

- **Access reviews** of eligibility, with certification checked at execution.
- **Audit export and checkpoints**, so `suit.audit.v1` evidence can be held
  and verified off the host.
- **Upstream packaging** in Debian and Fedora/EPEL.
- **1.0.0**, once the above hold.

## Not planned

A web terminal, SSH/RDP/database proxying, session recording, a credential
vault and a central console. They belong to a different product.
