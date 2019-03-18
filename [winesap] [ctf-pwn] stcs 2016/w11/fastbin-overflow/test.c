#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

sh() {
	system("/bin/sh");
}

int main() {
	void *p, *q, *r, *s;
	p = malloc(0x40);
	q = malloc(0x40);
	free(q);
	free(p);
	r = malloc(0x40);
	r = 
	s = malloc(0x40);
	return 0;
}
