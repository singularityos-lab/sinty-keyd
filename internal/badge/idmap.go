package badge

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

const holdEnv = "SINTY_KEYD_HOLD_NAMESPACE"

func Hold() bool {
	if os.Getenv(holdEnv) != "1" {
		return false
	}
	io.Copy(io.Discard, os.Stdin)
	return true
}

func MountMapped(src, dst string, diskUID, diskGID, uid, gid int) error {
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{holdEnv + "=1"}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: diskUID, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: diskGID, HostID: gid, Size: 1}},
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		stdin.Close()
		cmd.Wait()
	}()
	ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/user", cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer ns.Close()
	tree, err := unix.OpenTree(unix.AT_FDCWD, src, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		return fmt.Errorf("open_tree %s: %w", src, err)
	}
	defer unix.Close(tree)
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_IDMAP | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV, Userns_fd: uint64(ns.Fd())}
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &attr); err != nil {
		return fmt.Errorf("idmap %s: %w", src, err)
	}
	if err := unix.MoveMount(tree, "", unix.AT_FDCWD, dst, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("move mount to %s: %w", dst, err)
	}
	return nil
}
