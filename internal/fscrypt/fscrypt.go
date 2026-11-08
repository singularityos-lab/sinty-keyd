package fscrypt

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	specSize = 40
	argSize  = specSize + 4 + 4 + 32
)

func AddKey(dir string, raw []byte) (string, error) {
	if len(raw) != 64 {
		return "", errors.New("fscrypt keys are 64 bytes")
	}
	f, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, argSize+len(raw))
	defer clear(buf)
	binary.LittleEndian.PutUint32(buf[0:], unix.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER)
	binary.LittleEndian.PutUint32(buf[specSize:], uint32(len(raw)))
	copy(buf[argSize:], raw)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_ADD_ENCRYPTION_KEY, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", errno
	}
	return hex.EncodeToString(buf[8 : 8+unix.FSCRYPT_KEY_IDENTIFIER_SIZE]), nil
}

func RemoveKey(dir, id string) error {
	ident, err := hex.DecodeString(id)
	if err != nil || len(ident) != unix.FSCRYPT_KEY_IDENTIFIER_SIZE {
		return errors.New("bad key identifier")
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	var arg unix.FscryptRemoveKeyArg
	arg.Key_spec.Type = unix.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER
	copy(arg.Key_spec.U[:], ident)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_REMOVE_ENCRYPTION_KEY, uintptr(unsafe.Pointer(&arg))); errno != 0 {
		return errno
	}
	return nil
}

func SetPolicy(dir, id string) error {
	ident, err := hex.DecodeString(id)
	if err != nil || len(ident) != unix.FSCRYPT_KEY_IDENTIFIER_SIZE {
		return errors.New("bad key identifier")
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	p := unix.FscryptPolicyV2{
		Version:                   unix.FSCRYPT_POLICY_V2,
		Contents_encryption_mode:  unix.FSCRYPT_MODE_AES_256_XTS,
		Filenames_encryption_mode: unix.FSCRYPT_MODE_AES_256_CTS,
		Flags:                     unix.FSCRYPT_POLICY_FLAGS_PAD_16,
	}
	copy(p.Master_key_identifier[:], ident)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_SET_ENCRYPTION_POLICY, uintptr(unsafe.Pointer(&p))); errno != 0 {
		return errno
	}
	return nil
}
