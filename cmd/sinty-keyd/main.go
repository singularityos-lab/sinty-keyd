package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-keyd/internal/service"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

func main() {
	state := flag.String("state", "/run/sinty-keyd", "private directory for TPM operations")
	noTPM := flag.Bool("no-tpm", false, "never remember computers, every unlock is a guest unlock")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("sinty-keyd: ")
	if os.Getenv("DBUS_SYSTEM_BUS_ADDRESS") == "" {
		os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket")
	}
	cfg := service.Config{}
	if !*noTPM {
		h := tpm.NewHelper(*state)
		if _, err := h.Fingerprint(); err != nil {
			log.Printf("no TPM, guest unlock only: %v", err)
		} else {
			cfg.TPM = h
		}
	}

	var conn *dbus.Conn
	var err error
	for i := 0; ; i++ {
		conn, err = dbus.ConnectSystemBus()
		if err == nil {
			break
		}
		if i%10 == 0 {
			log.Printf("system bus not ready: %v", err)
		}
		time.Sleep(time.Second)
	}
	s := service.New(cfg)
	if err := service.Export(conn, s); err != nil {
		log.Fatal(err)
	}
	reply, err := conn.RequestName(service.Name, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("cannot own %s: %v", service.Name, err)
	}
	log.Printf("serving %s", service.Name)
	go func() {
		if err := s.FollowMounts(); err != nil {
			log.Printf("drive removal not followed: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	<-sigs
}
