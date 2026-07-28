//go:build !linux

package main

func runTelemetry(state *State, iface string, stop <-chan struct{}) { <-stop }
