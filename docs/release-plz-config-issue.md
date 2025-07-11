# Release-plz Configuration File Issue

## Problem Description

The release-plz GitHub Action was reporting "config file not found, using default configuration" despite having a `.release-plz.toml` file in the repository root. This was followed by git permission errors when the action attempted to perform git operations.

## Root Causes

1. **Working Directory Context**: GitHub Actions may not always run from the expected directory, causing release-plz to not find the configuration file.

2. **Insufficient Permissions**: GitHub changed the default repository workflow permissions from `write` to `read` in 2022, which prevents actions from creating pull requests or pushing to the repository.

3. **Configuration Discovery**: When release-plz can't find the config file, it falls back to default settings which include git operations (that the config was trying to disable).

## Solutions Applied

### 1. Updated Workflow Permissions

Modified both workflow files to include proper permissions:

```yaml
permissions:
  contents: write
  pull-requests: write
```

### 2. Repository Settings

The repository settings need to be updated:
- Go to Settings → Actions → General
- Under Workflow permissions, select:
  - "Read and write permissions"
  - "Allow GitHub Actions to create and approve pull requests"

### 3. Alternative: Personal Access Token

If permission issues persist, use a Personal Access Token:
1. Create a PAT with `repo` scope
2. Add it as a repository secret (e.g., `RELEASE_PLZ_TOKEN`)
3. Use it in the workflow: `GITHUB_TOKEN: ${{ secrets.RELEASE_PLZ_TOKEN }}`

## Configuration File Contents

The `.release-plz.toml` file attempts to disable git operations:

```toml
[workspace]
changelog_update = false
release_always = true

git_release_enable = false
git_tag_enable = false

[[package]]
name = "miden-testing"
semver_check = false
```

This configuration is designed to prevent release-plz from performing git operations, which is why it's critical that the file is found and loaded correctly.

## References

- [GitHub Actions default permissions change (2022)](https://github.blog/changelog/2023-02-02-github-actions-updating-the-default-github_token-permissions-to-read-only/)
- [Release-plz documentation](https://release-plz.dev/)