all: 1m-block

1m-block: 1m-block.o
	g++ -o 1m-block 1m-block.o -lnetfilter_queue

1m-block.o: main.cpp
	g++ -c -o 1m-block.o main.cpp

clean:
	rm -f 1m-block *.o
