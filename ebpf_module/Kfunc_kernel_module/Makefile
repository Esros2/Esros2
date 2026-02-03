obj-m += driver.o
ccflags-y += -g

VMLINUX_BTF_PATH ?= /sys/kernel/btf/vmlinux

all:
	make -C /lib/modules/$(shell uname -r)/build \
		M=$(PWD) \
		VMLINUX_BTF_PATH=$(VMLINUX_BTF_PATH) \
		modules

clean:
	make -C /lib/modules/$(shell uname -r)/build \
		M=$(PWD) clean
