#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	char buf[200];
	printf("say something: ");
	gets(buf);
	return 0;
}
