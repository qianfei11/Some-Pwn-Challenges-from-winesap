#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	void *p, *q, *r, *s;
	p = malloc(0x40);
	q = malloc(0x40);
	free(p);
	free(q);
	free(p);
}
