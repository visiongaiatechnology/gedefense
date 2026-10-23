// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"
	"errors"
)

// DesktopStatusServer has no transport outside Linux: the peer-credential check the socket relies
// on is a Linux facility, and the product itself is Linux-only. The type exists so the control
// plane still builds and its tests still run on a developer machine.
type DesktopStatusServer struct {
	cfg   DesktopConfig
	state *State
}

func NewDesktopStatusServer(cfg DesktopConfig, state *State) *DesktopStatusServer {
	return &DesktopStatusServer{cfg: cfg, state: state}
}

func (s *DesktopStatusServer) Start(ctx context.Context) error {
	if s == nil || !s.cfg.Enabled {
		return nil
	}
	return errors.New("desktop status socket requires Linux")
}
