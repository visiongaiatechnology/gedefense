//go:build !linux

package lpeguard

// ReadHostFacts reports the platform limitation: the kernel baseline sources
// (/proc/sys, /proc/modules, /etc/modprobe.d) are Linux interfaces. The empty
// facts make EvaluateHardening report every entry as unavailable, which is the
// honest answer on this platform.
func ReadHostFacts() HostFacts {
	return HostFacts{Modules: map[string]bool{}}
}
