# Alpine Ethernet uses the Rust descriptor model through a thin PCI adapter.
system_ss.add(files('alpine-eth.c', 'unifi-net.c', 'unifi-board.c', 'unifi-lcm.c'))
# The generic x86 PC target does not enable QEMU's SSI subsystem; the
# appliance SPI bridge is only needed by the ARM UniFi boards.
system_ss.add(when: 'CONFIG_SSI', if_true: files('alpine-dw-spi.c'))
