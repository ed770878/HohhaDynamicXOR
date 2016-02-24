LDFLAGS =
CFLAGS = -g -O3 -Wall

all: hohha hohha_brut
hohha: hohha.o hohha_util.o hohha_xor.o
hohha_brut: hohha_brut.o hohha_util.o hohha_xor.o

clean:
	rm -f hohha hohha_brut *.o

.PHONY: all clean
