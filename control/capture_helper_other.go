//go:build !linux

// STATUS: DIAMANT VGT SUPREME
package main

import "errors"

func runCaptureHelper(_ string) error {
	return errors.New("capture helper is only supported on Linux")
}
