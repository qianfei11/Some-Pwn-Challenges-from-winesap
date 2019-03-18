#include <stdio.h>
int main() {
	void (*ptr)();
	char buf[0x100];
	puts("shellcode>>");
	read(0, buf, 0x100);
	ptr = buf;
	ptr();
}
