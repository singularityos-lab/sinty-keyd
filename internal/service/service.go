package service

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-keyd/internal/fscrypt"
	"github.com/singularityos-lab/sinty-keyd/internal/hw"
	"github.com/singularityos-lab/sinty-keyd/internal/key"
	"github.com/singularityos-lab/sinty-keyd/internal/keyfile"
	"github.com/singularityos-lab/sinty-keyd/internal/seal"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

const (
	Name     = "dev.sinty.Key1"
	Path     = dbus.ObjectPath("/dev/sinty/Key1")
	Iface    = "dev.sinty.Key1"
	DataDir  = "Data"
	errorPfx = Iface + ".Error."
)

type Crypt interface {
	AddKey(dir string, raw []byte) (string, error)
	RemoveKey(dir, id string) error
	SetPolicy(dir, id string) error
}

type kernel struct{}

func (kernel) AddKey(dir string, raw []byte) (string, error) { return fscrypt.AddKey(dir, raw) }
func (kernel) RemoveKey(dir, id string) error                { return fscrypt.RemoveKey(dir, id) }
func (kernel) SetPolicy(dir, id string) error                { return fscrypt.SetPolicy(dir, id) }

type Config struct {
	TPM     tpm.TPM
	Crypt   Crypt
	Mounts  []string
	SysRoot string
}

type SlotInfo struct {
	PC       string
	Name     string
	Firmware string
	LastUsed int64
	Here     bool
}

type unlocked struct {
	mode string
	id   string
}

type Service struct {
	cfg   Config
	mu    sync.Mutex
	open  map[string]unlocked
	props *prop.Properties
}

func New(cfg Config) *Service {
	if cfg.Crypt == nil {
		cfg.Crypt = kernel{}
	}
	if cfg.SysRoot == "" {
		cfg.SysRoot = "/"
	}
	if len(cfg.Mounts) == 0 {
		cfg.Mounts = []string{"/run/media/", "/media/"}
	}
	return &Service{cfg: cfg, open: map[string]unlocked{}}
}

func Export(conn *dbus.Conn, s *Service) error {
	if err := conn.Export(s, Path, Iface); err != nil {
		return err
	}
	props, err := prop.Export(conn, Path, prop.Map{Iface: {
		"Unlocked": {Value: []string{}, Emit: prop.EmitTrue},
	}})
	if err != nil {
		return err
	}
	s.props = props
	node := &introspect.Node{
		Name: string(Path),
		Interfaces: []introspect.Interface{introspect.IntrospectData, prop.IntrospectData, {
			Name:       Iface,
			Methods:    introspect.Methods(s),
			Properties: props.Introspection(Iface),
		}},
	}
	return conn.Export(introspect.NewIntrospectable(node), Path, "org.freedesktop.DBus.Introspectable")
}

func fail(err error) *dbus.Error {
	name := "Failed"
	switch {
	case errors.Is(err, key.ErrWrongPIN):
		name = "WrongPin"
	case errors.Is(err, key.ErrWrongCode):
		name = "WrongCode"
	case errors.Is(err, key.ErrCopy):
		name = "Copy"
	case errors.Is(err, key.ErrShortPIN):
		name = "ShortPin"
	case errors.Is(err, key.ErrExists):
		name = "Exists"
	case errors.Is(err, key.ErrNotRemembered):
		name = "NotRemembered"
	case errors.Is(err, keyfile.ErrNoKey):
		name = "NotAKey"
	case errors.Is(err, keyfile.ErrTampered):
		name = "Tampered"
	case errors.Is(err, errPlace):
		name = "NotAllowed"
	}
	return dbus.NewError(errorPfx+name, []interface{}{err.Error()})
}

var errPlace = errors.New("only removable drives can hold a Sinty Key")

func (s *Service) place(root string) (string, error) {
	clean := filepath.Clean(root)
	if !filepath.IsAbs(clean) {
		return "", errPlace
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	for _, m := range s.cfg.Mounts {
		if strings.HasPrefix(real+"/", m) && real+"/" != m {
			return real, nil
		}
	}
	return "", errPlace
}

func (s *Service) publish() {
	if s.props == nil {
		return
	}
	list := make([]string, 0, len(s.open))
	for r := range s.open {
		list = append(list, r)
	}
	sort.Strings(list)
	s.props.SetMust(Iface, "Unlocked", list)
}

func (s *Service) here() string {
	if s.cfg.TPM == nil {
		return ""
	}
	pc, err := s.cfg.TPM.Fingerprint()
	if err != nil {
		return ""
	}
	return pc
}

func (s *Service) Inspect(root string) (string, string, string, []SlotInfo, *dbus.Error) {
	r, err := s.place(root)
	if err != nil {
		return "", "", "", nil, fail(err)
	}
	k, err := key.Open(r)
	if err != nil {
		return "", "", "", nil, fail(err)
	}
	s.mu.Lock()
	mode := s.open[r].mode
	s.mu.Unlock()
	here := s.here()
	slots := []SlotInfo{}
	for _, sl := range k.Header.Slots {
		slots = append(slots, SlotInfo{sl.PC, sl.Name, sl.Firmware, sl.LastUsed.Unix(), sl.PC == here})
	}
	return k.Header.ID, k.Header.Level, mode, slots, nil
}

func (s *Service) unlock(r string, master []byte, mode string) error {
	raw := key.DataKey(master)
	defer seal.Wipe(raw)
	data := filepath.Join(r, DataDir)
	if err := os.MkdirAll(data, 0o700); err != nil {
		return err
	}
	id, err := s.cfg.Crypt.AddKey(data, raw)
	if err != nil {
		return err
	}
	if entries, _ := os.ReadDir(data); len(entries) == 0 {
		if err := s.cfg.Crypt.SetPolicy(data, id); err != nil && !errors.Is(err, os.ErrExist) {
			log.Printf("%s: encryption policy: %v", data, err)
		}
	}
	s.open[r] = unlocked{mode: mode, id: id}
	s.publish()
	return nil
}

func (s *Service) Create(root, pin string) (string, *dbus.Error) {
	r, err := s.place(root)
	if err != nil {
		return "", fail(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, code, err := key.Create(r, pin)
	if err != nil {
		return "", fail(err)
	}
	master, mode, err := k.Unlock(nil, pin)
	if err != nil {
		return "", fail(err)
	}
	defer seal.Wipe(master)
	if err := s.unlock(r, master, mode); err != nil {
		return "", fail(err)
	}
	return code, nil
}

func (s *Service) Unlock(root, pin string) (string, *dbus.Error) {
	r, err := s.place(root)
	if err != nil {
		return "", fail(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.open[r]; ok {
		return u.mode, nil
	}
	k, err := key.Open(r)
	if err != nil {
		return "", fail(err)
	}
	master, mode, err := k.Unlock(s.cfg.TPM, pin)
	if err != nil {
		return "", fail(err)
	}
	defer seal.Wipe(master)
	if err := s.unlock(r, master, mode); err != nil {
		return "", fail(err)
	}
	return mode, nil
}

func (s *Service) Lock(root string) *dbus.Error {
	r, err := s.place(root)
	if err != nil {
		return fail(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.open[r]
	if !ok {
		return nil
	}
	if err := s.cfg.Crypt.RemoveKey(filepath.Join(r, DataDir), u.id); err != nil {
		return fail(err)
	}
	delete(s.open, r)
	s.publish()
	return nil
}

func (s *Service) withKey(root string, fn func(*key.Key) error) *dbus.Error {
	r, err := s.place(root)
	if err != nil {
		return fail(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := key.Open(r)
	if err != nil {
		return fail(err)
	}
	if err := fn(k); err != nil {
		return fail(err)
	}
	return nil
}

func (s *Service) Remember(root, pin, name string) *dbus.Error {
	if s.cfg.TPM == nil {
		return dbus.NewError(errorPfx+"NoTpm", []interface{}{"this computer has no TPM"})
	}
	if strings.TrimSpace(name) == "" {
		name = hw.Name(s.cfg.SysRoot)
	}
	return s.withKey(root, func(k *key.Key) error {
		return k.Remember(s.cfg.TPM, pin, name, hw.FirmwareFamily(s.cfg.SysRoot))
	})
}

func (s *Service) Forget(root, pin, pc string) *dbus.Error {
	return s.withKey(root, func(k *key.Key) error {
		return k.Forget(s.cfg.TPM, pin, pc)
	})
}

func (s *Service) ChangePin(root, old, pin string) *dbus.Error {
	return s.withKey(root, func(k *key.Key) error {
		return k.ChangePIN(s.cfg.TPM, old, pin)
	})
}

func (s *Service) Recover(root, code, pin string) *dbus.Error {
	return s.withKey(root, func(k *key.Key) error {
		return k.Recover(s.cfg.TPM, code, pin)
	})
}
