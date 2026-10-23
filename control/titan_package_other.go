// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"
	"errors"
)

type titanUnsupportedPackageVerifier struct{}

func newTitanPackageVerifier() titanPackageVerifier { return titanUnsupportedPackageVerifier{} }

// Owner reports missing evidence on non-Linux platforms; the trust engine then
// lowers trust instead of assuming package ownership.
func (titanUnsupportedPackageVerifier) Owner(context.Context, string) (titanPackageOwner, bool, error) {
	return titanPackageOwner{}, false, errors.New("package ownership evidence requires Linux")
}
