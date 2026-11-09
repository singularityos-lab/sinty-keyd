# sinty-keyd

The Sinty Key service of Sinty OS. A Sinty Key is a USB drive with your
encrypted data, opened with your PIN on any Sinty OS computer. It is the only
process that touches the Key's master key and the TPM.

The login screen asks it which Keys are plugged in and attaches the user's Key
after login. Settings uses it to create, unlock, back up and restore Keys.

## D-Bus

`dev.sinty.Key1` on the system bus, object `/dev/sinty/Key1`. `root` is the
mount point of the Key under `/run/media/` or `/media/`.

| Member | Signature | |
|---|---|---|
| `Present` | property `a(ssss)` | Keys plugged in: device, id, owner, state (`locked`, `copy`, `guest`, `trusted`). |
| `Unlocked` | property `as` | Mount points of the unlocked Keys. |
| `Attach(device, user, pin)` | in `sss`, out `ss` | Mounts the Key for `user` and unlocks it. Login screen and root only. |
| `Inspect(root)` | in `s`, out `sssa(sssxb)` | Id, level, state and the remembered computers. |
| `Create(root, pin)` | in `ss`, out `s` | Returns the recovery code. |
| `Unlock(root, pin)` / `Lock(root)` | | |
| `Remember(root, pin, name)` / `Forget(root, pin, fingerprint)` | | Seal the Key in this computer's TPM, or drop the seal. |
| `ChangePin(root, old, new)` / `Recover(root, code, pin)` | | |
| `Backup(root, pin, fd)` / `Restore(fd, code, root, pin)` | | Restore returns the new recovery code. |
| `Devices()` / `Revoke(kind, id)` | | Devices this computer trusts: Keys, screens and phones. |
| `Trust(kind, id, name)` | in `sss` | Adds a screen or phone. System services only. |
| `Revoked(kind, id)` | signal | |

Errors are `dev.sinty.Key1.Error.` followed by `WrongPin`, `WrongCode`,
`Copy`, `ShortPin`, `Exists`, `NotAKey`, `NotRemembered`, `Tampered`,
`NotAllowed`, `NoTpm`, `NotABackup`, `Damaged`, `Unknown` or `Failed`.

## Building

```sh
make
make test
make install DESTDIR=...
```

Requires Go >= 1.25 and Linux.
