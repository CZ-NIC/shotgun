
bpf-reflect.o: bpf-reflect.ll
	llc -march=bpf -filetype=obj -o bpf-reflect.o bpf-reflect.ll

bpf-reflect.ll: bpf-reflect.c bpf_endian.h parsing_helpers.h
	clang -S -target bpf -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -O2 -emit-llvm -c -g   -Wno-unused-command-line-argument -Icontrib/bpf $(pkg-config --cflags-only-I libknot) -DNDEBUG -o bpf-reflect.ll bpf-reflect.c

clean:
	rm -f bpf-reflect.{o,ll}

# Useful commands:
#   eth=eth6
# Shows line with "prog/xdp id NNN" if a program is loaded.
#   ip link show $eth
#
#   sudo ip link set dev $eth xdp off
#   sudo ip link set dev $eth xdp obj ./bpf-reflect.o sec xdp_reflect_udp

