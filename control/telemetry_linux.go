//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type cpuCounters struct{ total, idle uint64 }

func readCPU() (cpuCounters, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuCounters{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuCounters{}, fmt.Errorf("empty /proc/stat")
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, fmt.Errorf("invalid /proc/stat")
	}
	var vals []uint64
	for _, x := range fields[1:] {
		v, e := strconv.ParseUint(x, 10, 64)
		if e != nil {
			return cpuCounters{}, e
		}
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4]
	}
	return cpuCounters{total: total, idle: idle}, nil
}
func readMemory() (used, total uint64, err error) {
	f, e := os.Open("/proc/meminfo")
	if e != nil {
		return 0, 0, e
	}
	defer f.Close()
	vals := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) >= 2 {
			v, _ := strconv.ParseUint(p[1], 10, 64)
			vals[strings.TrimSuffix(p[0], ":")] = v * 1024
		}
	}
	total = vals["MemTotal"]
	avail := vals["MemAvailable"]
	if total >= avail {
		used = total - avail
	}
	return used, total, sc.Err()
}
func readUintFile(path string) (uint64, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return 0, e
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}
func runTelemetry(state *State, iface string, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	prevCPU, _ := readCPU()
	var prevRX, prevTX uint64
	var prevTime = time.Now()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			curCPU, _ := readCPU()
			var cpu float64
			dt := curCPU.total - prevCPU.total
			if dt > 0 {
				cpu = 100 * float64(dt-(curCPU.idle-prevCPU.idle)) / float64(dt)
			}
			prevCPU = curCPU
			used, total, _ := readMemory()
			rx, _ := readUintFile("/sys/class/net/" + iface + "/statistics/rx_bytes")
			tx, _ := readUintFile("/sys/class/net/" + iface + "/statistics/tx_bytes")
			secs := now.Sub(prevTime).Seconds()
			var rxRate, txRate float64
			if secs > 0 {
				rxRate = float64(rx-prevRX) / secs
				txRate = float64(tx-prevTX) / secs
			}
			prevRX, prevTX, prevTime = rx, tx, now
			var mem float64
			if total > 0 {
				mem = 100 * float64(used) / float64(total)
			}
			state.SetTelemetry(Telemetry{CPUPercent: cpu, MemoryPercent: mem, MemoryUsed: used, MemoryTotal: total, RXBytes: rx, TXBytes: tx, RXRate: rxRate, TXRate: txRate, Interface: iface})
		}
	}
}
