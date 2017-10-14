CFLAGS=-g -std=c99 -pedantic -Wall

get: get.o
	gcc get.o -o get

get.o: get.c
	gcc -c $(CFLAGS) get.c

put: put.o
	gcc put.o -o put

put.o: put.c
	gcc -c $(CFLAGS) put.c

clean:
	rm -f get get.o put.o put.c
