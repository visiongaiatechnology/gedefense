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
	Available bool                      `json:"available"`
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
}

func NewPackageIntegrityScanner() *PackageIntegrityScanner {
	return newPackageIntegrityScanner("/var/lib/pacman/local", "/")
}

func newPackageIntegrityScanner(dbRoot, fsRoot string) *PackageIntegrityScanner {
	return &PackageIntegrityScanner{
		dbRoot: dbRoot,
		fsRoot: fsRoot,
		status: PackageIntegrityStatus{Available: packageIntegritySupported(), Findings: []PackageIntegrityFinding{}},
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
	if !s.status.Available {
		s.mu.Unlock()
		return errors.New("package integrity scanner is unavailable")
	}
	s.status.Running = true
	s.status.Error = ""
	s.mu.Unlock()

	go func() {
		status, err := scanPackageIntegrity(s.dbRoot, s.fsRoot)
		status.Available = true
		status.Running = false
		now := time.Now().UTC()
		status.LastScan = &now
		if err != nil {
			status.Error = "package integrity scan failed closed"
			status.Errors++
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
