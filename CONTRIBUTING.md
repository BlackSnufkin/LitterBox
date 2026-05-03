# Contributing to LitterBox

Thanks for considering a contribution. This file is the short version of how to land a useful change without a long review cycle.

## What we welcome

- Bug fixes (with a clear repro)
- New analyzers / scanners — see [New Scanner](../../wiki/New-Scanner) on the wiki
- New / improved YARA rules — see [YARA Rules Management](../../wiki/YARA-Rules-Management)
- Wiki improvements — corrections, missing detail, screenshots
- New EDR profile examples (`Config/edr_profiles/<name>.yml.example`) for backends we haven't documented yet
- Performance and code-quality improvements with measurable impact

## What we won't merge

- Style-only refactors that touch many files for no functional gain
- Speculative abstractions ("this might be useful later") with no current consumer
- Changes that introduce new third-party dependencies without a clear justification
- "Add my tool to the stack" PRs without integration code, docs, and a sample run

## Dev setup

```bash
git clone https://github.com/BlackSnufkin/LitterBox.git
cd LitterBox
python -m venv venv
.\venv\Scripts\Activate.ps1                # Windows
pip install -r requirements.txt
python litterbox.py --debug                # http://127.0.0.1:1337
```

Architecture overview lives in the wiki: [Application Architecture](../../wiki/Application-Architecture).

## Branching + PR workflow

- Work in a feature branch on a personal fork.
- Open the PR against `main`. We don't maintain release branches.
- PR description: what changed, why, and a one-line repro / sanity check.
- Add new commits to fix review feedback — don't force-push the branch unless asked.

## Commit messages

Match the style in `git log --oneline`:

- One short imperative subject line, ~70 chars max
- Optional body for the "why" — bullets, no padding
- No `Co-Authored-By:` trailers
- Don't enumerate every changed file in the message — the diff already does that

Example:
```
EDR — gate killed_by_edr on alert evidence

Otherwise a benign payload that crashes on its own gets a false-positive
"killed by EDR" label.
```

## Code expectations

- **Pyflakes clean** — no unused imports, no unused locals. We sweep these regularly.
- **Follow existing patterns** before introducing new ones. New analyzers go through `BaseSubprocessAnalyzer`; new EDR profiles use the existing `EdrProfile` shape.
- **No silent fallbacks for things that should fail loud.** If a config field is required, raise on missing — don't paper over it.
- **No comments narrating what the code obviously does.** Comments belong where the *why* isn't obvious from the identifier names.

## Verifying changes

There is no automated test suite at the moment. Before opening a PR:

1. Boot LitterBox: `python litterbox.py --debug` — no errors at startup, dashboard renders.
2. Exercise the path you changed end-to-end. For analyzer changes, upload a sample and watch the result page populate. For EDR changes, dispatch against a registered profile.
3. If you touched anything user-visible, update the relevant wiki page in the same PR (or in a follow-up clearly linked from the PR).

## Security disclosures

If you find a vulnerability, **do not open a public issue.** Report it via [GitHub Security Advisories](https://github.com/BlackSnufkin/LitterBox/security/advisories) on this repo, or contact the maintainer privately. Public disclosure before a fix lands gets users compromised.

## License

By contributing to LitterBox, you agree your contributions will be licensed under the terms in [LICENSE](LICENSE).
