CFLAGS = -g -O3 -Wall -MMD -MF.dep/$@.d
LDFLAGS =

$(shell mkdir -p .dep)

all: hohha hohha_crc hohha_brut
hohha: hohha.o hohha_util.o hohha_xor.o
hohha_crc: hohha_crc.o hohha_util.o
hohha_brut: hohha_brut.o hohha_util.o hohha_xor.o
-include $(wildcard .dep/*.d)

clean:
	rm -f hohha hohha_brut *.o
	rm -rf .dep/

.PHONY: all clean
