#include <stdio.h>

int main() {
	setvbuf(stdout, 0, _IONBF, 0);
	alarm(180);
	char str[100];
	while(gets(str)) {
		printf(str);
	}
	return 0;
}
