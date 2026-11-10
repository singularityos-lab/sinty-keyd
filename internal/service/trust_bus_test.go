package service

import (
	"bufio"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/fido2"
)

func TestTrustAndRevokeOverTheBus(t *testing.T) {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	addr, _ := bufio.NewReader(out).ReadString('\n')
	addr = strings.TrimSpace(addr)
	server, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	s, _, _, _ := setup(t, "pc-a")
	s.cfg.TrustFile = filepath.Join(t.TempDir(), "trusted.json")
	if err := Export(server, s); err != nil {
		t.Fatal(err)
	}
	server.RequestName(Name, dbus.NameFlagDoNotQueue)
	client, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	obj := client.Object(Name, Path)

	if err := obj.Call(Iface+".Trust", 0, KindKey, "abc", "x").Err; err == nil {
		t.Fatal("a Key was trusted without remembering it")
	}
	if err := obj.Call(Iface+".Trust", 0, "screen", "9f2c", "Living Room").Err; err != nil {
		t.Fatal(err)
	}
	var list []DeviceInfo
	if err := obj.Call(Iface+".Devices", 0).Store(&list); err != nil || len(list) != 1 || list[0].Name != "Living Room" {
		t.Fatalf("devices: %+v %v", list, err)
	}

	client.AddMatchSignal(dbus.WithMatchInterface(Iface), dbus.WithMatchMember("Revoked"))
	sig := make(chan *dbus.Signal, 4)
	client.Signal(sig)
	if err := obj.Call(Iface+".Revoke", 0, "screen", "9f2c").Err; err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sig:
		if len(got.Body) != 2 || got.Body[0] != "screen" || got.Body[1] != "9f2c" {
			t.Fatalf("revoked signal: %v", got.Body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no Revoked signal")
	}
	if err := obj.Call(Iface+".Devices", 0).Store(&list); err != nil || len(list) != 0 {
		t.Fatalf("still trusted: %+v", list)
	}
}

func TestSecurityKeysOverTheBus(t *testing.T) {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	addr, _ := bufio.NewReader(out).ReadString('\n')
	addr = strings.TrimSpace(addr)
	server, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	s, _, _, drive := setup(t, "pc-a")
	usb := &plugged{keys: []*fido2.Soft{fido2.NewSoft()}}
	s.keys = securityKeys{open: usb.open}
	if err := Export(server, s); err != nil {
		t.Fatal(err)
	}
	server.RequestName(Name, dbus.NameFlagDoNotQueue)
	client, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	obj := client.Object(Name, Path)
	if err := obj.Call(Iface+".Create", 0, drive, "482915").Err; err != nil {
		t.Fatal(err)
	}
	var id string
	if err := obj.Call(Iface+".AddSecurityKey", 0, drive, "482915", "Blue", "").Store(&id); err != nil || id == "" {
		t.Fatalf("add: %q %v", id, err)
	}
	var list []SecurityKeyInfo
	if err := obj.Call(Iface+".SecurityKeys", 0, drive).Store(&list); err != nil || len(list) != 1 || list[0].ID != id {
		t.Fatalf("list: %+v %v", list, err)
	}
	usb.keys = nil
	obj.Call(Iface+".Lock", 0, drive)
	err = obj.Call(Iface+".Unlock", 0, drive, "482915").Err
	if e, ok := err.(dbus.Error); !ok || e.Name != errorPfx+"SecurityKeyRequired" {
		t.Fatalf("unlock without the security key: %v", err)
	}
	var xml string
	if err := obj.Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&xml); err != nil || !strings.Contains(xml, `name="SecurityKeys"`) || !strings.Contains(xml, `type="a(ssx)"`) {
		t.Fatalf("introspection: %v", err)
	}
}
