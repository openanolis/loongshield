# Makefile for kmod

TARGET = sysmon

ifneq ($(KERNELRELEASE),)
	ccflags-y += -I$(PWD)/../lib/
	ccflags-y += -DBASENAME='"${TARGET}"'
	ccflags-y += -DFILTER_PROFILE
	ccflags-y += -DDEBUG
	ccflags-y += -Wno-unused-function -Wno-incompatible-pointer-types -Wno-date-time
	#ccflags-y += -mno-fentry

	ldflags-y += -T $(PWD)/kmain.lds

	obj-m := ${TARGET}.o

	${TARGET}-y :=   \
		kmain.o      \
		ctor.o       \
		debug.o      \
		securityfs.o \
		filter.o     \
		flt_kernel.o
else
	ifneq ($(wildcard /lib/modules/$(shell uname -r)/build/.*),)
		# for ubuntu
		KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	else
		# for centos
		KERNELDIR ?= /usr/src/kernels/$(shell uname -r)
	endif
	PWD := $(shell pwd)

.PHONY: all

all: default

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	strip --strip-unneeded ${TARGET}.ko

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif
