# Contributing to ProofLog

Thanks for looking. A few ground rules that keep this project small and
trustworthy:

1. **Every behaviour change needs a test.** Especially a negative test:
   if you change verification, add a case where a bad log must fail.
2. **Zero dependencies, one main file.** `prooflog.py` should stay
   copy-pasteable. If a feature needs a third-party package, it probably
   belongs in a separate tool, not here.
3. **Be honest about security claims.** This is tamper-evident, not
   tamper-proof — do not describe it otherwise in code, docs, or PRs.
4. **Keep the CLI boring.** Flags should be obvious; output should be
   readable by a non-programmer (an auditor will read `verify` output).

## Workflow

```bash
python -m unittest -v   # all tests must pass before you open a PR
```

Open an issue first for anything bigger than a bug fix, so design can be
discussed before code is written. Small, focused PRs get reviewed fastest.
