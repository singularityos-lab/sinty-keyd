package hw

import (
	"os"
	"path/filepath"
	"testing"
)

func device(t *testing.T, root, slot, class, vendor string) {
	t.Helper()
	d := filepath.Join(root, "sys/bus/pci/devices", slot)
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "class"), []byte(class+"\n"), 0o644)
	os.WriteFile(filepath.Join(d, "vendor"), []byte(vendor+"\n"), 0o644)
}

func TestFirmwareFamily(t *testing.T) {
	root := t.TempDir()
	if f := FirmwareFamily(root); f != "generic" {
		t.Fatalf("no devices: %s", f)
	}
	device(t, root, "0000:00:02.0", "0x030000", "0x8086")
	device(t, root, "0000:00:1f.3", "0x040300", "0x10de")
	if f := FirmwareFamily(root); f != "intel" {
		t.Fatalf("intel only, audio ignored: %s", f)
	}
	device(t, root, "0000:01:00.0", "0x030200", "0x10de")
	if f := FirmwareFamily(root); f != "nvidia" {
		t.Fatalf("hybrid with nvidia: %s", f)
	}
}

func TestName(t *testing.T) {
	root := t.TempDir()
	if Name(root) != "Computer" {
		t.Fatal("fallback")
	}
	os.MkdirAll(filepath.Join(root, "sys/class/dmi/id"), 0o755)
	os.WriteFile(filepath.Join(root, "sys/class/dmi/id/product_name"), []byte("To Be Filled By O.E.M.\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/hostname"), []byte("desk\n"), 0o644)
	if Name(root) != "desk" {
		t.Fatalf("placeholder DMI name: %s", Name(root))
	}
	os.WriteFile(filepath.Join(root, "sys/class/dmi/id/product_name"), []byte("Yoga Slim 7\n"), 0o644)
	if Name(root) != "Yoga Slim 7" {
		t.Fatal(Name(root))
	}
}
