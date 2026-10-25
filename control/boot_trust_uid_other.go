//go:build !linux

// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import "os"

// fileInfoUid has no portable owner information off Linux; the ownership check
// is skipped there and the mode check remains in force.
func fileInfoUid(os.FileInfo) (uint32, bool) { return 0, false }
