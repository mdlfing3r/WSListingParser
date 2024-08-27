CC=gcc

all: WSLP

WSLP: main.c
	$(CC) main.c -o WSLP -lpcap

clean:
	rm -rf *.o WSLP

