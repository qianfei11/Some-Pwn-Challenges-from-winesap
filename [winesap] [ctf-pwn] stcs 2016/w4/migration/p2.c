#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vul() {
	char buf[50];
	printf("say something: ");
	gets(buf);
}

int main() {
	vul();
	return 0;
}
