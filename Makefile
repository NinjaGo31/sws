PROG = sws
OBJS = sws.o util.o
CFLAGS = -ansi -g -Wall -Werror -Wextra -Wformat=2 -Wjump-misses-init -Wlogical-op -Wpedantic -Wshadow

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${CFLAGS} ${OBJS} -o ${PROG}

sws.o:
	${CC} ${CFLAGS} -c sws.c

util.o: util.c util.h
	${CC} ${CFLAGS} -c util.c

clean:
	rm -rf ${OBJS} ${PROG}