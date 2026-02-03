APP=ebpfMod

.PHONY: ebpfMod
ebpfMod: skel
	clang-14 ebpfMod.c -lbpf -o ebpfMod

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
		clang-14  -g -O2 -target bpf -c ebpfMod.bpf.c -o ebpfMod.bpf.o


.PHONY: skel
skel: bpf
	bpftool gen skeleton ebpfMod.bpf.o name ebpfMod > ebpfMod.skel.h
	rm ebpfMod.bpf.o

.PHONY: run
run: $(APP)
	sudo ./$(APP)
