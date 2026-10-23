//go:build !linux

package main

import (
	"context"
	"errors"
)

func watchIntegrityChanges(context.Context, []string) (<-chan struct{}, func(), error) {
	return nil, func() {}, errors.New("native integrity event watcher is unavailable on this platform")
}
