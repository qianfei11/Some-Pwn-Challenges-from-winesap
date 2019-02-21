#include <stdio.h>
#include <string.h>

void a() {
	char buf[100];
	gets(buf);
	puts(buf);
}

int main() {
	a();
}
