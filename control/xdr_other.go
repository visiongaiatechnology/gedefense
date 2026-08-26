//go:build !linux

package main

import "errors"

func scanLinuxProcesses(int) (map[string]ProcessSample, error) {
	return nil, errors.New("XDR sensor requires Linux")
}
func correlateLinuxConnections(map[string]ProcessSample) (map[string][]NetConnection, int) {
	return nil, 0
}

func readExecProcess(CoreExecEvent, int) (ProcessSample, error) {
	return ProcessSample{}, errors.New("kernel exec sensor is only supported on Linux")
}
