LDFLAGS =
CFLAGS = -g -O3 -Wall

hohha: hohha.o hohha_util.o hohha_xor.o

clean:
	rm -f hohha hohha.o hohha_util.o hohha_xor.o
