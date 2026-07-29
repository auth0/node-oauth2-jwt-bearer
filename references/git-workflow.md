# Git Workflow

## Branches

- Default/base branch is `main`. Per `CONTRIBUTING.md`: fork the repo, create a well-named branch, and open a PR.
- No branch-name linting is enforced; use a short descriptive name (e.g. `fix/dpop-iat-window`).

## Before you commit

- Run the checks CI enforces: `npm test` (all workspaces) and `npm run lint`. Code changes must be accompanied by tests covering the changed/added functionality, and coverage must stay at 100%.
- No git hooks are configured in this repo; run the commands manually.

## Commits & PRs

- No commitlint/Conventional-Commits enforcement is configured; write clear, imperative commit subjects. (The `CHANGELOG.md` in the published package is produced by the release process — don't hand-edit it in feature PRs.)
- Fill out the PR template completely (see `CONTRIBUTING.md` and Auth0's [general contributing guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)).
- Open PRs against `main`. CI (`.github/workflows/test.yml`) must pass: build + unit tests on Node 20/22/24 and lint. Security workflows (CodeQL, Snyk, rl-secure) also run.
- Security issues go through the [Responsible Disclosure Program](https://auth0.com/whitehat), not the public issue tracker.
