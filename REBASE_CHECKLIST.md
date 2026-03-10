# Rebase Checklist (Fork Workflow)

This repo uses the split-branch model:
- `base-master` tracks upstream (`base/master`)
- `master` is your fork’s clean base
- `custom-*` branches carry the squashed fork changes

## Quick Rebase Steps

1. Update the upstream mirror
   - `git fetch base`
   - `git checkout base-master`
   - `git reset --hard base/master`

2. Rebase fork master onto upstream
   - `git checkout master`
   - `git rebase base-master`

3. Rebase your custom branch
   - `git checkout custom-3.6.x` (or current custom branch)
   - `git rebase master`

4. Resolve conflicts (likely hotspots)
   - `cmd/traefik/traefik.go`
   - `pkg/config/static/static_config.go`
   - Generated docs/config files under `docs/` and `docs/content/reference/*`

5. Regenerate schema/docs
   - `make generate`

6. Run targeted tests (fast sanity)
   - `go test ./pkg/provider/acmeredux -count=1`
   - `go test ./pkg/provider/vaultpki -count=1`
   - Add integration tags when needed:
     - `go test ./pkg/provider/acmeredux -tags=integration -count=1`
     - `go test ./pkg/provider/vaultpki -tags=integration -count=1`

7. Review git status and diff
   - `git status -sb`
   - `git diff --stat`

## Notes

- `acmeredux` is Vault-only and uses `vaultStorage.key` for the KV key.
- `vaultpki` integration tests require `VAULT_ADDR`/`VAULT_TOKEN` or `BAO_ADDR`/`BAO_TOKEN`.
- After rebase, re-run `make generate` to sync config/docs.
