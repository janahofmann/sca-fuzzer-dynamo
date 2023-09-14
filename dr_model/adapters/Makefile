all: adapter

CFLAGS = -ggdb

adapter: adapter.o
	gcc  -o adapter $^ -lrt -ggdb

example: example_adapter.o
	gcc  -o example $^ -ggdb
