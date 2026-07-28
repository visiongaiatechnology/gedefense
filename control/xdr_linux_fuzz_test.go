//go:build linux

package main

import "testing"

func FuzzProcStatParser(f *testing.F) {
	f.Add("123 (worker name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 20")
	f.Add("")
	f.Add("1 (() R 0")
	f.Fuzz(func(t *testing.T, stat string) {
		if len(stat) > 1<<20 {
			t.Skip()
		}
		ppid, start, comm, err := parseProcStat(stat)
		if err == nil {
			if ppid < 0 {
				t.Fatalf("accepted negative parent PID: %d", ppid)
			}
			if start == 0 {
				t.Fatal("accepted zero process start ticks")
			}
			if len(comm) > len(stat) {
				t.Fatal("parser returned a command name longer than its input")
			}
		}
	})
}
