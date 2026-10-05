# Keyring-Utilities Changelog

## `3.6.0`

- Enhancement: SHA-256/AES-256 CBC is now the default algorithm for private key export. To maintain backward compatibility, the legacy SHA-1/RC4 algorithm can be enabled using the "-c" option. [#26](https://github.com/zowe/keyring-utilities/pull/26)

## `3.2.0`

- `--label-only` and `--owner-only` flags no longer print summary header, and only print certificate content. [#21](https://github.com/zowe/keyring-utilities/pull/21)

## `3.0.0`

- Added manifest.yaml to PAX file which includes build metadata (#18)
- Added Github Action build, deprecated Jenkins build (#13)
- Added `LISTRING` command to keyring-utilities (#13)
- Modified `EXPORT` to output password-protected .p12 private keys instead of PEMs (#13)
- Modified all commands to support command-line parameters (#13)
- Deprecated node-binding for keyring-utilities (#13)