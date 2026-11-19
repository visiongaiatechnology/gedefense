//go:build linux

package flowguard

import (
	"errors"
	"fmt"
	"syscall"
)

// Classic-BPF opcode shorthands used by the generated handshake prefilter.
const (
	bpfLdHalfBytes   = syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS
	bpfLdByte        = syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS
	bpfLdHalfInd     = syscall.BPF_LD | syscall.BPF_H | syscall.BPF_IND
	bpfLdLenMSH      = syscall.BPF_LDX | syscall.BPF_B | syscall.BPF_MSH
	bpfJumpEqual     = syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K
	bpfReturn        = syscall.BPF_RET | syscall.BPF_K
	bpfAcceptVerdict = 0xffff
	bpfDropVerdict   = 0
)

// Maximum number of configured ports the prefilter is generated for. It mirrors
// CaptureConfig.Normalize so the kernel program and the userspace decoder walk
// the same bounded port set.
const maxFilterPorts = 8

// cBPF label used by the builder below. Labels are resolved to instruction
// offsets in one final pass, which keeps the generator linear and readable.
type cBPFJump struct {
	instruction int
	label       int
	onTrue      bool
}

type cBPFBuilder struct {
	program []syscall.SockFilter
	labels  []int
	jumps   []cBPFJump
}

func (b *cBPFBuilder) newLabel() int {
	b.labels = append(b.labels, -1)
	return len(b.labels) - 1
}

func (b *cBPFBuilder) mark(label int) {
	b.labels[label] = len(b.program)
}

func (b *cBPFBuilder) add(code uint16, k uint32) int {
	b.program = append(b.program, syscall.SockFilter{Code: code, K: k})
	return len(b.program) - 1
}

// jumpIfEqual emits `jeq k, <true label>, fallthrough` (Jf = 0). The false
// branch simply continues with the next instruction.
func (b *cBPFBuilder) jumpIfEqual(k uint32, trueLabel int) {
	instruction := b.add(bpfJumpEqual, k)
	b.jumps = append(b.jumps, cBPFJump{instruction: instruction, label: trueLabel, onTrue: true})
}

func (b *cBPFBuilder) compile() ([]syscall.SockFilter, error) {
	for _, jump := range b.jumps {
		target := b.labels[jump.label]
		if target < 0 {
			return nil, errors.New("flowguard: unresolved BPF jump label")
		}
		offset := target - (jump.instruction + 1)
		if offset < 0 || offset > 0xff {
			return nil, fmt.Errorf("flowguard: BPF jump offset %d is out of range", offset)
		}
		if jump.onTrue {
			b.program[jump.instruction].Jt = uint8(offset)
		} else {
			b.program[jump.instruction].Jf = uint8(offset)
		}
	}
	if len(b.program) == 0 || len(b.program) > syscall.BPF_MAXINSNS {
		return nil, fmt.Errorf("flowguard: generated BPF program has %d instructions", len(b.program))
	}
	return b.program, nil
}

// handshakeBPF generates the classic BPF prefilter from the configured ports:
//
//	ethertype IPv4
//	  TCP -> destination port in config.Ports
//	  UDP -> destination port in config.Ports
//	ethertype IPv6 (plain 40-byte header, no extension headers)
//	  TCP -> destination port in config.Ports
//	  UDP -> destination port in config.Ports
//
// The program uses the standard `ldx 4*([14]&0xf)` IPv4-header-length trick so a
// header with options is handled; the IPv6 layout is fixed. The payload
// first-byte predicate needs the TCP data offset and is applied in userspace
// (decodeFrame), where a bounded copy is already made.
func handshakeBPF(ports []uint16) ([]syscall.SockFilter, error) {
	ports = uniquePorts(ports, maxFilterPorts)
	if len(ports) == 0 {
		return nil, errors.New("flowguard: at least one capture port is required")
	}
	builder := &cBPFBuilder{}
	accept := builder.newLabel()
	ipv4 := builder.newLabel()
	ipv6 := builder.newLabel()
	ipv4TCP := builder.newLabel()
	ipv4UDP := builder.newLabel()
	ipv6TCP := builder.newLabel()
	ipv6UDP := builder.newLabel()

	// Dispatch on the Ethernet type; anything that is not IPv4/IPv6 is dropped.
	builder.add(bpfLdHalfBytes, 12) // A = EtherType
	builder.jumpIfEqual(ethPIPv4, ipv4)
	builder.jumpIfEqual(ethPIPv6, ipv6)
	builder.add(bpfReturn, bpfDropVerdict)

	builder.mark(ipv4)
	builder.add(bpfLdByte, 23) // A = IPv4 protocol (14 + 9)
	builder.jumpIfEqual(ipProtoTCP, ipv4TCP)
	builder.jumpIfEqual(ipProtoUDP, ipv4UDP)
	builder.add(bpfReturn, bpfDropVerdict)

	builder.mark(ipv4TCP)
	builder.add(bpfLdLenMSH, 14)  // X = 4 * (IPv4 header length)
	builder.add(bpfLdHalfInd, 16) // A = TCP destination port (X + 16)
	for _, port := range ports {
		builder.jumpIfEqual(uint32(port), accept)
	}
	builder.add(bpfReturn, bpfDropVerdict)

	builder.mark(ipv4UDP)
	builder.add(bpfLdLenMSH, 14)
	builder.add(bpfLdHalfInd, 16) // A = UDP destination port (X + 16)
	for _, port := range ports {
		builder.jumpIfEqual(uint32(port), accept)
	}
	builder.add(bpfReturn, bpfDropVerdict)

	builder.mark(ipv6)
	builder.add(bpfLdByte, 20) // A = IPv6 next header (14 + 6)
	builder.jumpIfEqual(ipProtoTCP, ipv6TCP)
	builder.jumpIfEqual(ipProtoUDP, ipv6UDP)
	builder.add(bpfReturn, bpfDropVerdict)

	builder.mark(ipv6TCP)
	builder.add(bpfLdHalfBytes, 56) // TCP destination port (14 + 40 + 2)
	for _, port := range ports {
		builder.jumpIfEqual(uint32(port), accept)
	}
	builder.add(bpfReturn, bpfDropVerdict)

	builder.mark(ipv6UDP)
	builder.add(bpfLdHalfBytes, 56) // UDP destination port (14 + 40 + 2)
	for _, port := range ports {
		builder.jumpIfEqual(uint32(port), accept)
	}
	builder.add(bpfReturn, bpfDropVerdict)

	builder.mark(accept)
	builder.add(bpfReturn, bpfAcceptVerdict)
	return builder.compile()
}

// uniquePorts removes duplicates, preserves order and bounds the list so the
// generated program stays far below BPF_MAXINSNS and the 8-bit jump range.
func uniquePorts(ports []uint16, max int) []uint16 {
	out := make([]uint16, 0, minInt(len(ports), max))
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			continue
		}
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
		if len(out) >= max {
			break
		}
	}
	return out
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
