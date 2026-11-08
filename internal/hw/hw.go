package hw

import (
	"os"
	"path/filepath"
	"strings"
)

var vendors = map[string]string{
	"0x10de": "nvidia",
	"0x1002": "amd",
	"0x8086": "intel",
}

func FirmwareFamily(root string) string {
	devices, _ := filepath.Glob(filepath.Join(root, "sys/bus/pci/devices/*"))
	found := map[string]bool{}
	for _, d := range devices {
		class, err := os.ReadFile(filepath.Join(d, "class"))
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(class)), "0x03") {
			continue
		}
		vendor, err := os.ReadFile(filepath.Join(d, "vendor"))
		if err != nil {
			continue
		}
		if f, ok := vendors[strings.TrimSpace(string(vendor))]; ok {
			found[f] = true
		}
	}
	for _, f := range []string{"nvidia", "amd", "intel"} {
		if found[f] {
			return f
		}
	}
	return "generic"
}

func Name(root string) string {
	for _, f := range []string{"product_name", "board_name"} {
		if b, err := os.ReadFile(filepath.Join(root, "sys/class/dmi/id", f)); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" && !strings.Contains(strings.ToLower(s), "to be filled") {
				return s
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "etc/hostname")); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return "Computer"
}
