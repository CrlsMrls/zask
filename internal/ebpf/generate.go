// Package ebpf provides eBPF program loading, map management, and kernel interaction.
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $BPF_STRIP -cflags $BPF_CFLAGS -target bpfel -type exec_key -type event Zask ../../bpf/zask.c
