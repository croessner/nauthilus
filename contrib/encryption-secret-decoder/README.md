# Nauthilus Encryption Secret Decoder

This helper decodes values written by the Nauthilus `server/security.Manager`, for example encrypted Redis or LDAP values backed by an `encryption_secret`.

Run it from the repository root:

```shell
make build-encryption-secret-decoder
nauthilus/bin/encryption-secret-decoder
```

The helper prompts for `encryption_secret` with masked input. The encrypted value can be entered interactively, passed as the optional positional argument, piped through stdin, or loaded from a file:

```shell
nauthilus/bin/encryption-secret-decoder < encrypted-value.txt
nauthilus/bin/encryption-secret-decoder -ciphertext-file encrypted-value.txt
```

Plaintext is written to stdout as a printable, single-line representation. Non-printable bytes are escaped so binary plaintext cannot corrupt the terminal.
