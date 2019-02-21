#include <stdio.h>
#include <string.h>
int main() {
	char str[100];
	char bb[10];
	memset(str, 'a', 100);
	fgets(bb, 10, stdin);
	strncpy(str, bb, 5);
	puts(str);
	return 0;
}
