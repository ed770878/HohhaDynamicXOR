LDFLAGS =
CFLAGS = -g -O0 -Wall

hohha: hohha.o hohha_util.o hohha_xor.o

clean:
	rm hohha hohha_util.o hohha_xor.o
