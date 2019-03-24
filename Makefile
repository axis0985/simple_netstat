all: helper.o
	$(CC) hw1.c helper.o -o hw1
obj: helper.c
	$(CC) helper.c -c
.PHONY: clean
clean: 
	rm -f helper.o
	rm -f hw1