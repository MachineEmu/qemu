obj-m += kvm_analysis_guard.o
kvm_analysis_guard-y := kvm_analysis_guard_main.o kvm_analysis_measure.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean check

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

check:
	test -d "$(KDIR)" || { echo "missing kernel build tree: $(KDIR)" >&2; exit 1; }
	test -r "$(KDIR)/Module.symvers" || echo "warning: $(KDIR)/Module.symvers not found" >&2
