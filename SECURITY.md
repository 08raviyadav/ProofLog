# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please do not open a public issue for a security problem. Open a private
report on the GitHub repository (Security tab → Report a vulnerability) or
contact the maintainer through GitHub, describing the issue and how to
reproduce it. You will get a response, and a fix or a workaround, before
anything is disclosed publicly.

## Scope note

ProofLog provides tamper *evidence* for audit records. It does not, by
itself, provide authentication, authorisation, or non-repudiation. Deployments
that need those properties must add them (per-actor signing, access control,
and independent archiving of log hashes) — see the README's limitations
section before relying on ProofLog for a compliance decision.
