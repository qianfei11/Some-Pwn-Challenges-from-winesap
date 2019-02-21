#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char good[200]; // global

int main() {
	char buf[100]; // stack
	char *magic = malloc(300); // heap
	gets(buf);
	strcpy(good, buf);
	strcpy(magic, good);
	puts(magic);
}
