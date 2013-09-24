program=bbootimg
CC?=gcc
OPT=-O2 ${CFLAGS}
OBJ=bbootimg.o libbootimg.o

.PHONY: build
.PHONY: install
.PHONY: uninstall
.PHONY: clean

build: ${program}

clean:
	rm -f *.o ${program}

${program}: ${OBJ}
	$(CC) ${OBJ} -o ${program} ${OPT}

bbootimg.o: bbootimg.c
	$(CC) -c ${OPT} $<

libbootimg.o: libbootimg.c
	$(CC) -c ${OPT} $<

install: build
	install -D ${program} /usr/local/bin/${program}

uninstall:
	rm /usr/local/bin/${program}
