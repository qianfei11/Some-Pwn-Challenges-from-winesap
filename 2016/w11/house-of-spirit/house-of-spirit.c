#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char buf[128];
char *ptr[8];
char *cmd;
int size;
int n = 0;

void sh(char *c) {
	system(c);
}

int main() {
	setvbuf(stdout, 0, _IONBF, 0);
	memset(ptr, 0, sizeof(ptr));
	cmd = buf;

	while (1) {
		fgets(cmd, sizeof(buf), stdin);
		if (!strncmp(cmd, "push", 4)) {
			if (n<8) {
				scanf("%d%*c", &size);
				ptr[n] = malloc(size);
				fgets(ptr[n], size, stdin);
				n++;
			} else {
				puts("stack is full");
			}
		} else if (! strncmp(cmd, "pop", 3)) {
			if (n>=0) {
				n--;
				puts(ptr[n]);
				free(ptr[n]);
				ptr[n] = 0;
			} else {
				puts("stack is empty");
			}
		} else {
			puts("unknown command");
		}
	}
}
