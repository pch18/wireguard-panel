# Repository instructions

## Production releases and deployments

- When the user asks to release or deploy this project, read `DEPLOYMENT.md` first.
- Production target details must come from the repository-local `wireguard-panel.*` Git config or
  the documented environment variables. Never commit or print private-key contents.
- Release committed and tested code before production deployment. Deploy the immutable release tag
  with `scripts/deploy-alpine.sh`; do not deploy an uncommitted worktree or a mutable branch build.
- After deployment, run `scripts/deploy-alpine.sh --check` and report the Release tag, service state,
  internal and external health checks, and whether rollback was needed.
