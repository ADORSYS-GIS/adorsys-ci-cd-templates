# Gitleaks Pre-Commit Hook

The project repositories use Gitleaks to scan staged changes before every commit. The hook works with terminal commits and IDE commits because Git runs it directly.

## Activate

From the project root, install Gitleaks, then run:

```bash
sudo apt update
sudo apt install gitleaks
./scripts/branch_commits/setup_hooks.sh
```

Run this in each project repository:


## Behavior

- A detected secret stops the commit.
- Gitleaks not being installed also stops the commit.
- Fix or unstage the finding, then retry the commit.

The hook uses Gitleaks' staged scan and scans staged changes only.
