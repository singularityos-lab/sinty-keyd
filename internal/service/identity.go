package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/godbus/dbus/v5"
	"github.com/singularityos-lab/sinty-identity/device"

	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

const IdentityAction = "dev.sinty.key.identity-confirm"

var errNoIdentity = errors.New("no identity key")

func (s *Service) identityDir(uid uint32) string {
	return filepath.Join(s.cfg.IdentityDir, strconv.FormatUint(uint64(uid), 10))
}

func readAll(dir string, names ...string) ([][]byte, error) {
	out := make([][]byte, len(names))
	for i, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func writeAll(dir string, files map[string][]byte) error {
	tmp := dir + ".new"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(tmp, n), b, 0o600); err != nil {
			os.RemoveAll(tmp)
			return err
		}
	}
	return os.Rename(tmp, dir)
}

// identityPoint returns the public point of uid's key, x then y, and whether
// it lives in the TPM.
func (s *Service) identityPoint(uid uint32) ([]byte, bool, error) {
	dir := s.identityDir(uid)
	if b, err := readAll(dir, "point"); err == nil {
		return b[0], true, nil
	}
	b, err := readAll(dir, "key")
	if err != nil {
		return nil, false, errNoIdentity
	}
	k, err := x509.ParseECPrivateKey(b[0])
	if err != nil {
		return nil, false, err
	}
	return append(k.X.FillBytes(make([]byte, 32)), k.Y.FillBytes(make([]byte, 32))...), false, nil
}

func (s *Service) createIdentity(uid uint32) error {
	if err := os.MkdirAll(s.cfg.IdentityDir, 0o700); err != nil {
		return err
	}
	if s.cfg.TPM != nil {
		auth := make([]byte, 32)
		if _, err := rand.Read(auth); err != nil {
			return err
		}
		pub, priv, point, err := s.cfg.TPM.NewSigningKey(auth)
		if err != nil {
			return err
		}
		return writeAll(s.identityDir(uid), map[string][]byte{"auth": auth, "pub": pub, "priv": priv, "point": point})
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return writeAll(s.identityDir(uid), map[string][]byte{"key": der})
}

func (s *Service) identitySign(uid uint32, digest []byte) ([]byte, error) {
	dir := s.identityDir(uid)
	if b, err := readAll(dir, "auth", "pub", "priv"); err == nil {
		if s.cfg.TPM == nil {
			return nil, tpm.ErrUnavailable
		}
		return s.cfg.TPM.Sign(b[0], b[1], b[2], digest)
	}
	b, err := readAll(dir, "key")
	if err != nil {
		return nil, errNoIdentity
	}
	k, err := x509.ParseECPrivateKey(b[0])
	if err != nil {
		return nil, err
	}
	r, sv, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...), nil
}

func identityError(name string, err error) *dbus.Error {
	return dbus.NewError(errorPfx+name, []interface{}{err.Error()})
}

// IdentityKey returns the caller's device identity key, made on first use:
// its public point and whether it lives in the TPM.
func (s *Service) IdentityKey(sender dbus.Sender) ([]byte, bool, *dbus.Error) {
	uid, err := s.senderUID(sender)
	if err != nil {
		return nil, false, identityError("NotAllowed", err)
	}
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	point, hw, err := s.identityPoint(uid)
	if errors.Is(err, errNoIdentity) {
		if err := s.createIdentity(uid); err != nil {
			return nil, false, identityError("Failed", err)
		}
		point, hw, err = s.identityPoint(uid)
	}
	if err != nil {
		return nil, false, identityError("Failed", err)
	}
	return point, hw, nil
}

// IdentitySign signs a sinty-identity message with the caller's key. A
// message that acts for the person, such as allowing a sign-in, needs the
// person to confirm with their PIN first.
func (s *Service) IdentitySign(sender dbus.Sender, message []byte) ([]byte, *dbus.Error) {
	uid, err := s.senderUID(sender)
	if err != nil {
		return nil, identityError("NotAllowed", err)
	}
	if _, _, ok := device.Parse(message); !ok {
		return nil, identityError("NotAllowed", errors.New("only sign-in messages are signed"))
	}
	if device.Acts(message) {
		if derr := s.confirm(sender, IdentityAction); derr != nil {
			return nil, identityError("NotConfirmed", errors.New("not confirmed"))
		}
	}
	sum := sha256.Sum256(message)
	s.identityMu.Lock()
	sig, err := s.identitySign(uid, sum[:])
	s.identityMu.Unlock()
	switch {
	case errors.Is(err, errNoIdentity):
		return nil, identityError("NoIdentityKey", err)
	case errors.Is(err, tpm.ErrLockedOut):
		return nil, identityError("LockedOut", err)
	case err != nil:
		return nil, identityError("Failed", err)
	}
	return sig, nil
}

// ForgetIdentityKey removes the caller's key. Devices enrolled with it stop
// answering until enrolled again.
func (s *Service) ForgetIdentityKey(sender dbus.Sender) *dbus.Error {
	uid, err := s.senderUID(sender)
	if err != nil {
		return identityError("NotAllowed", err)
	}
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	dir := s.identityDir(uid)
	if b, err := readAll(dir, "auth"); err == nil {
		wipeFile(filepath.Join(dir, "auth"), len(b[0]))
	}
	if b, err := readAll(dir, "key"); err == nil {
		wipeFile(filepath.Join(dir, "key"), len(b[0]))
	}
	if err := os.RemoveAll(dir); err != nil {
		return identityError("Failed", err)
	}
	return nil
}

func wipeFile(path string, n int) {
	os.WriteFile(path, make([]byte, n), 0o600)
}
