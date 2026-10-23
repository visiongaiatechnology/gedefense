// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"
	"errors"
)

type titanUnsupportedObserver struct{}

func newTitanPlatformObserver() titanObserver { return &titanUnsupportedObserver{} }

// Run reports the explicit unavailable state instead of pretending to observe.
func (o *titanUnsupportedObserver) Run(context.Context, []string, chan<- titanObservation) error {
	return errors.New("Titan file observation requires the Linux inotify sensor")
}
