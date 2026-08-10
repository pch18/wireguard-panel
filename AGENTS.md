# Repository instructions

## Production releases and deployments

- When the user asks to release or deploy this project, read `DEPLOYMENT.md` first.
- Never store deployment target addresses, SSH users, or private-key paths in the repository.
- Release committed and tested code before production deployment. Run `install-alpine.sh` directly
  on each target server; test and production servers use the same installer.
- After deployment, report the Release tag, service state, local health check, and external health check.

## Modal stacking

- When a modal opens another modal, keep the original modal mounted and visible beneath the new one so users retain context and unsaved input.
- Use exactly one visual backdrop for the active modal stack. Place the original modal below that backdrop and the newest modal above it; do not stack multiple backdrop opacities or blur layers.
- Only the topmost modal is interactive and responds to keyboard dismissal or focus trapping. Closing it must restore the previous modal without resetting its state.
