# Contributing to SuperSCP

Thanks for your interest in improving SuperSCP.

## Before You Start
- Open an issue for major changes so scope and design can be aligned first.
- For bug fixes, include clear reproduction steps.

## Development Workflow
1. Fork the repository and create a branch.
2. Make focused changes.
3. Validate locally:
   - `python3 -m py_compile superscp.py`
   - Run example commands from `manpage.md` where applicable.
4. Update docs if behavior or flags changed.
5. Submit a pull request with:
   - What changed
   - Why it changed
   - How it was tested

## Coding Guidelines
- Preserve `scp` compatibility unless a change is explicitly superscp-only.
- Prefer clear error messages and actionable failures.
- Keep changes minimal and easy to review.

## Pull Request Checklist
- [ ] Code compiles and runs.
- [ ] New/changed flags are documented.
- [ ] Error handling is covered by tests or manual validation.
- [ ] No unrelated refactors included.

## Code of Conduct
By participating, you agree to follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
