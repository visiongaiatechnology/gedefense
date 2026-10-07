//go:build !linux

// STATUS: DIAMANT VGT SUPREME
package main

// The web-surface scan reads /proc, which exists only on Linux. The honest answer on
// another platform is "not scanned", never "nothing found": reporting an empty surface
// would read as "no web server is running", which is a claim this code cannot support.
// These are development hosts for the control plane, not deployment targets.

func discoverWebSurface() WebSurface {
	return WebSurface{Scanned: false, Reason: "web surface discovery requires Linux"}
}

func describeWebSurface(surface WebSurface, attached bool) string {
	if !surface.Scanned {
		return "web surface not scanned: " + surface.Reason
	}
	if !surface.ExpectsHTTP {
		return "no web server or web port detected on this host"
	}
	if attached {
		return "web surface detected and an L7 traffic path is attached"
	}
	return "web surface detected but no L7 traffic path is attached; HTTP traffic is not being inspected"
}
