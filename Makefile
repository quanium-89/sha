HDR=sha.h
SRC=sha.c

all: $(HDR) $(SRC) test.c
	gcc test.c $(SRC) -o test

clean:
	rm -f test
