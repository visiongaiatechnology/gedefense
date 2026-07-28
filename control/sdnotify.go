package main

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func sdNotify(message string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	addr, err := net.ResolveUnixAddr("unixgram", socket)
	if err != nil {
		return err
	}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(message))
	return err
}

func startSystemdWatchdog(ctx context.Context, status func() string) {
	raw := strings.TrimSpace(os.Getenv("WATCHDOG_USEC"))
	usec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || usec <= 0 {
		return
	}
	interval := time.Duration(usec) * time.Microsecond / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			message := "WATCHDOG=1"
			if detail := strings.TrimSpace(status()); detail != "" {
				message += "\nSTATUS=" + strings.ReplaceAll(detail, "\n", " ")
			}
			_ = sdNotify(message)
		}
	}
}
