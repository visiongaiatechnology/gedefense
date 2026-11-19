//go:build !linux

package webposture

import "context"

// discoverServers reports the platform limitation honestly instead of pretending
// a web server inventory was collected.
func discoverServers(_ context.Context, _ int) ([]Server, []string, string) {
	return nil, []string{"web posture discovery requires /proc and debug/elf on Linux"}, "web posture discovery is only available on Linux"
}

func fillListenersFromProcNet(_ *Server, _ []ConfigFile) {}
