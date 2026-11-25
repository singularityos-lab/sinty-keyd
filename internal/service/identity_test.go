package service

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/singularityos-lab/sinty-identity/device"
)

type busKey struct {
	obj dbus.BusObject
	pub *ecdsa.PublicKey
}

func (k *busKey) Public() *ecdsa.PublicKey { return k.pub }

func (k *busKey) SignDigest([]byte) ([]byte, error) { panic("whole messages only") }

func (k *busKey) SignMessage(msg []byte) ([]byte, error) {
	var sig []byte
	err := k.obj.Call(Iface+".IdentitySign", 0, msg).Store(&sig)
	return sig, err
}

func identityBus(t *testing.T, tpmName string, confirmed *bool, asked *int) (dbus.BusObject, *Service) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	addr, _ := bufio.NewReader(out).ReadString('\n')
	addr = strings.TrimSpace(addr)
	server, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	s, _, _, _ := setup(t, tpmName)
	if tpmName == "" {
		s.cfg.TPM = nil
	}
	s.cfg.IdentityDir = filepath.Join(t.TempDir(), "identity")
	s.cfg.Confirm = func(dbus.Sender, string) *dbus.Error {
		*asked++
		if *confirmed {
			return nil
		}
		return dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", nil)
	}
	if err := Export(server, s); err != nil {
		t.Fatal(err)
	}
	server.RequestName(Name, dbus.NameFlagDoNotQueue)
	client, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client.Object(Name, Path), s
}

func openKey(t *testing.T, obj dbus.BusObject) (*busKey, bool) {
	t.Helper()
	var point []byte
	var hw bool
	if err := obj.Call(Iface+".IdentityKey", 0).Store(&point, &hw); err != nil || len(point) != 64 {
		t.Fatalf("identity key: %v %d", err, len(point))
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(point[:32]), Y: new(big.Int).SetBytes(point[32:])}
	return &busKey{obj: obj, pub: pub}, hw
}

func TestIdentityKeyAsksOnlyWhenActing(t *testing.T) {
	for _, tc := range []struct {
		name string
		tpm  string
		hw   bool
	}{{"tpm", "pc-a", true}, {"no tpm", "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			confirmed, asked := false, 0
			obj, s := identityBus(t, tc.tpm, &confirmed, &asked)
			k, hw := openKey(t, obj)
			if hw != tc.hw {
				t.Fatalf("hardware = %v", hw)
			}
			again, _ := openKey(t, obj)
			if device.ID(again) != device.ID(k) {
				t.Fatal("the key changed between calls")
			}

			poll := device.PollMessage("https://id.example", device.ID(k), 1)
			sig, err := device.Sign(k, poll)
			if err != nil || !device.Verify(k.pub, poll, sig) || asked != 0 {
				t.Fatalf("poll: %v asked=%d", err, asked)
			}
			deny := device.ApproveMessage("https://id.example", "a", "n", "it", "42", false)
			if sig, err := device.Sign(k, deny); err != nil || !device.Verify(k.pub, deny, sig) || asked != 0 {
				t.Fatalf("refusal: %v asked=%d", err, asked)
			}

			allow := device.ApproveMessage("https://id.example", "a", "n", "it", "42", true)
			if _, err := device.Sign(k, allow); err == nil || asked != 1 {
				t.Fatalf("an approval was signed without confirmation: %v asked=%d", err, asked)
			}
			confirmed = true
			if sig, err := device.Sign(k, allow); err != nil || !device.Verify(k.pub, allow, sig) || asked != 2 {
				t.Fatalf("confirmed approval: %v asked=%d", err, asked)
			}

			var raw []byte
			if err := obj.Call(Iface+".IdentitySign", 0, []byte("anything at all")).Store(&raw); err == nil {
				t.Fatal("a message of another protocol was signed")
			}

			dir := s.identityDir(uint32(os.Getuid()))
			if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
				t.Fatalf("key directory: %v %v", fi, err)
			}
			absent := "auth"
			if tc.hw {
				absent = "key"
			}
			if _, err := os.Stat(filepath.Join(dir, absent)); !os.IsNotExist(err) {
				t.Fatalf("%s kept for a %s key", absent, tc.name)
			}
			if err := obj.Call(Iface+".ForgetIdentityKey", 0).Err; err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("the key outlived Forget")
			}
			if _, err := device.Sign(k, poll); err == nil {
				t.Fatal("a forgotten key still signs")
			}
		})
	}
}
