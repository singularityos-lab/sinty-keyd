# sinty-keyd

The Sinty Key service of Sinty OS. A Sinty Key is a USB drive that carries
your encrypted data and unlocks it on any Sinty OS computer with your PIN. On
computers you choose to remember, the key is also sealed in that computer's
TPM, which limits wrong PIN attempts and refuses older copies of the Key.

sinty-keyd is the only process that handles the Key's master key and the
TPM. The greeter, Settings and the installer talk to it over D-Bus.

## How a Key is built

A Key keeps a header in `.sinty-key/key.json` and the encrypted data in
`Data/`, which is protected with fscrypt (v2 policy, AES-256-XTS for
contents, AES-256-CTS for names).

The master key is never stored in the clear. The header holds it wrapped
three ways:

| Wrap | Opened by |
|---|---|
| Guest | Argon2id (t=3, 64 MiB) over the PIN and a random secret stored on the Key, then XChaCha20-Poly1305. Works on any computer. |
| Recovery | The recovery code shown when the Key is made, same construction. |
| One slot per remembered computer | That computer's TPM, sealed under the PIN. The TPM's lockout throttles wrong PINs. |

The header is authenticated with an HMAC keyed from the master key, so an
edited header is refused once the key is opened.

### Older copies

Every remembered computer has a monotonic counter in its TPM. Each unlock
there writes the next value into the Key and then advances the counter. A
copy of the Key made earlier carries a smaller value and is refused on that
computer (`Copy`); only the recovery code gets past it. Recovering on a
remembered computer, or forgetting the computer you are on, also advances its
counter, so a lost Key stops working there.

### Changing the PIN

The guest wrap and the slot of the current computer are sealed again at
once. Slots on other computers still hold the old PIN; their next unlock with
the new PIN falls back to the guest wrap and seals the slot again.

## Starting a computer from a Key

The installer's "Install on: A Sinty Key" writes the whole system to the
drive: the ESP with the Atom Loops loader, the verified root image and a data
partition marked portable. The loader records the partition it started from,
so the Key boots its own system and data even on a computer that has Sinty OS
installed.

On a portable system, `sintykey` keeps the login key sealed in the TPM of the
computer where the PIN was set and also wrapped under the PIN with Argon2id.
A computer whose TPM never sealed it unlocks the wrapped copy. Without the
TPM's lockout, failed attempts are counted on the Key: after three, each
attempt waits 5 seconds, doubling up to one hour.

## D-Bus

The service owns `dev.sinty.Key1` on the system bus at `/dev/sinty/Key1` and
is started on demand. `root` is the mount point of the Key and must be on a
removable drive (`/run/media/...` or `/media/...`).

| Member | Signature | |
|---|---|---|
| `Inspect(root)` | in `s`, out `sssa(sssxb)` | Id, level, `trusted`, `guest` or empty when locked, and the remembered computers: fingerprint, name, firmware family, last unlock (Unix time), whether it is this computer. |
| `Create(root, pin)` | in `ss`, out `s` | Makes the drive a Key and returns the recovery code. The Key is left unlocked. |
| `Unlock(root, pin)` | in `ss`, out `s` | `trusted` on a remembered computer, `guest` elsewhere. Adds the data key to the kernel. |
| `Lock(root)` | in `s` | Removes the data key. |
| `Remember(root, pin, name)` | in `sss` | Seals the Key in this computer's TPM. An empty name uses the computer's model. |
| `Forget(root, pin, fingerprint)` | in `sss` | |
| `ChangePin(root, old, new)` | in `sss` | |
| `Recover(root, code, pin)` | in `sss` | Sets a new PIN with the recovery code. |
| `Unlocked` | property `as` | Mount points of the unlocked Keys. |

Errors are `dev.sinty.Key1.Error.` followed by `WrongPin`, `WrongCode`,
`Copy`, `ShortPin`, `Exists`, `NotAKey`, `NotRemembered`, `Tampered`,
`NotAllowed`, `NoTpm` or `Failed`.

```sh
gdbus call --system --dest dev.sinty.Key1 --object-path /dev/sinty/Key1 \
  --method dev.sinty.Key1.Inspect /run/media/alex/KEY
```

## TPM

TPM operations go through `/usr/libexec/sintykey-tpm`, the helper that also
seals the login key, with the PIN and keys passed in 0600 files. Besides
`seal` and `unseal`, sinty-keyd uses:

```
sintykey-tpm ek-fingerprint            # stdout: hex SHA-256 of the endorsement key
sintykey-tpm counter-define            # stdout: index of a new NV counter
sintykey-tpm counter-read  <index>     # stdout: value
sintykey-tpm counter-bump  <index>     # stdout: new value
```

Without a TPM, or with `--no-tpm`, every unlock is a guest unlock.

## Building

```sh
make
make test
make install DESTDIR=...
```

Requires Go >= 1.25 and Linux. The non-stdlib dependencies are
`github.com/godbus/dbus/v5` and `golang.org/x/crypto`.
