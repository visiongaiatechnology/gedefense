// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"sync"
	"time"
)

const packageIntegrityMaxFindings = 500

type PackageIntegrityFinding struct {
	Package string `json:"package"`
	Path    string `json:"path"`
	Status  string `json:"status"`
}

type PackageIntegrityStatus struct {
	Available bool `json:"available"`
	// Supported states whether this host has the package database the scanner
	// can verify. On a distribution it does not support, the scanner is honestly
	// "not supported" instead of failing its next scan: a pacman database cannot
	// be missing because the host is insecure.
	Supported bool                      `json:"supported"`
	Reason    string                    `json:"reason,omitempty"`
	Running   bool                      `json:"running"`
	LastScan  *time.Time                `json:"last_scan,omitempty"`
	Packages  int                       `json:"packages"`
	Files     int                       `json:"files"`
	Verified  int                       `json:"verified"`
	Modified  int                       `json:"modified"`
	Missing   int                       `json:"missing"`
	Errors    int                       `json:"errors"`
	Findings  []PackageIntegrityFinding `json:"findings"`
	Error     string                    `json:"error,omitempty"`
}

type PackageIntegrityScanner struct {
	mu     sync.RWMutex
	dbRoot string
	fsRoot string
	status PackageIntegrityStatus
	policy packagePolicy
}

func NewPackageIntegrityScanner() *PackageIntegrityScanner {
	return newPackageIntegrityScanner("/var/lib/pacman/local", "/")
}

func newPackageIntegrityScanner(dbRoot, fsRoot string) *PackageIntegrityScanner {
	supported, reason := packageIntegritySupportedFor(dbRoot)
	return &PackageIntegrityScanner{
		dbRoot: dbRoot,
		fsRoot: fsRoot,
		status: PackageIntegrityStatus{
			Available: supported, Supported: supported, Reason: reason,
			Findings: []PackageIntegrityFinding{},
		},
		policy: defaultIntegrityFabricSettings(Config{}).Packages.policy(),
	}
}

func (s *PackageIntegrityScanner) Status() PackageIntegrityStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := s.status
	status.Findings = append([]PackageIntegrityFinding(nil), s.status.Findings...)
	return status
}

func (s *PackageIntegrityScanner) Start(onComplete func(PackageIntegrityStatus)) error {
	s.mu.Lock()
	if s.status.Running {
		s.mu.Unlock()
		return errors.New("package integrity scan already running")
	}
	if !s.status.Supported {
		s.mu.Unlock()
		return errors.New("package integrity scanner is not supported on this host")
	}
	if !s.status.Available {
		s.mu.Unlock()
		return errors.New("package integrity scanner is unavailable")
	}
	s.status.Running = true
	s.status.Error = ""
	s.mu.Unlock()

	go func() {
		status, err := scanPackageIntegrity(s.dbRoot, s.fsRoot)
		status.Running = false
		now := time.Now().UTC()
		status.LastScan = &now
		if err != nil {
			// A package database that is absent is a platform property, not a
			// deviation: report "not supported" with the reason instead of a
			// red failed scan, and never count it as an integrity error.
			if supported, reason := packageIntegritySupportedFor(s.dbRoot); !supported {
				status.Available = false
				status.Supported = false
				status.Reason = reason
				status.Errors = 0
				status.Error = ""
			} else {
				status.Available = true
				status.Supported = true
				status.Error = "package integrity scan failed closed"
				status.Errors++
			}
		} else {
			status.Available = true
			status.Supported = true
			status.Reason = ""
		}
		s.mu.Lock()
		s.status = status
		s.mu.Unlock()
		if onComplete != nil {
			onComplete(s.Status())
		}
	}()
	return nil
}
