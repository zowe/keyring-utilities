# Keyring-Utilities Changelog

## `3.2.0`

- `--label-only` and `--owner-only` flags no longer print summary header, and only print certificate content. [#21](https://github.com/zowe/keyring-utilities/pull/21)

## `3.0.0`

- Added manifest.yaml to PAX file which includes build metadata (#18)
- Added Github Action build, deprecated Jenkins build (#13)
- Added `LISTRING` command to keyring-utilities (#13)
- Modified `EXPORT` to output password-protected .p12 private keys instead of PEMs (#13)
- Modified all commands to support command-line parameters (#13)
- Deprecated node-binding for keyring-utilities (#13)