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
| `SecurityKeys(root)` | in `s`, out `a(ssx)` | FIDO2 security keys registered with the Key: id, name, time added. |
| `AddSecurityKey(root, pin, name, keyPin)` | in `ssss`, out `s` | Registers the plugged-in security key. From then on the Key opens only with PIN, security key and, where remembered, the TPM. `keyPin` is the security key's own PIN, empty if it has none. |
| `RemoveSecurityKey(root, pin, id)` | | Removing the last one turns the Key back into PIN and TPM only. |
| `RecoverWithoutSecurityKeys(root, code, pin)` | | Sets a new PIN with the recovery code and drops every security key. |
| `Backup(root, pin, fd)` / `Restore(fd, code, root, pin)` | | Restore returns the new recovery code. |
| `Devices()` / `Revoke(kind, id)` | | Devices this computer trusts: Keys, screens and phones. |
| `Trust(kind, id, name)` | in `sss` | Adds a screen or phone. System services only. |
| `Revoked(kind, id)` | signal | |
| `Badge` | property `s` | Id of the Key whose session is open on this computer, empty if none. |
| `BadgeAllowed` | property `b` | Whether this computer opens sessions from a Key without a local account. |
| `Badge(device, pin)` | in `ss`, out `ss` | Opens a session from the Key: returns the user (`sinty-badge`) and a one-time ticket for the login. Login screen and root only. |
| `ResumeBadge(pin)` | in `s` | Unlocks the session again after the Key was taken out and plugged back in. |
| `EndBadge()` | | Ends the session, removes the account and unmounts the Key. |
| `SetBadgeAllowed(on)` | in `b` | Administrators only. Stored in `/etc/sinty/key-badge`. |
| `StartupSync(device)` | in `s`, out `sss` | For a startup Key: which side is older (`key`, `computer` or empty), the Key's version and this computer's. Only the same architecture, and only when the newer side keeps the signed release of its version. |
| `UpdateStartupKey(device)` | in `s` | Stages this computer's release into the Key's slots without the network. The Key tries it on its next start and falls back if it does not boot. |
| `UpdateFromStartupKey(device)` | in `s` | Administrators only. Stages the Key's release on this computer like an update from the network; it is tried on the next restart. |
| `BadgeKeyRemoved` / `BadgeKeyReturned` | signal | The session's Key was taken out, or is back. Without it the session ends after two minutes. |

Errors are `dev.sinty.Key1.Error.` followed by `WrongPin`, `WrongCode`,
`Copy`, `ShortPin`, `Exists`, `NotAKey`, `NotRemembered`, `Tampered`,
`NotAllowed`, `NoTpm`, `NotABackup`, `Damaged`, `Unknown`,
`SecurityKeyRequired`, `UnknownSecurityKey`, `SecurityKeyExists`,
`TooManySecurityKeys`, `NoSecurityKey`, `NotTouched`, `SecurityKeyPinRequired`,
`WrongSecurityKeyPin`, `SecurityKeyPinBlocked`, `SecurityKeyUnsupported`,
`Disabled`, `Unverified`, `Busy` or `Failed`.

A security key must support the CTAP2 `hmac-secret` extension. Its secret
joins the PIN and the Key's own secret in the derivation of the master key,
and masks what the TPM seals. The recovery code opens the Key without one.

A session from a Key runs as the transient account `sinty-badge` (uid 61000).
The Key's home is mounted on `/run/sinty-badge/home` through an idmapped mount,
so files keep the Key's own owner on disk. The computer opens one only when it
boots a verified system: a `sing.roothash=` on the command line, kernel lockdown
on and the root on a verity device.

## Building

```sh
make
make test
make install DESTDIR=...
```

Requires Go >= 1.25 and Linux.
