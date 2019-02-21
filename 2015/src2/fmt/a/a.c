#include <stdio.h>

int x;

int main() {
	char str[100];
	gets(str);
	x = 0;
	printf(str);
	printf("%08x\n", x);
}
