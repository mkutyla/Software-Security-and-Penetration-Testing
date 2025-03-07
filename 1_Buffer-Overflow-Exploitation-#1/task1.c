/* gcc task1.c -o task1 -m32 -ggdb -no-pie -z execstack -fno-stack-protector -fcf-protection=none -std=c89 -Wno-deprecated-declarations */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum UserIds {
    Zwiedzajacy = 0,
    Administracja = 1,
    Dyrektor = 0x1337
};

int main(void) {
    char name[0x10];
    int userId = (int)Zwiedzajacy;

    setbuf(stdout, NULL);

    printf("Podaj nick:");
    gets(name);
    printf("Witaj %s!\n", name);

    if(userId == Dyrektor) {
        puts("Oto flaga: ");
        FILE* f = fopen("flag.txt", "rb");
        char* ptr = (char*)malloc(0x100);
        memset(ptr, 0, 0x100);
        fread(ptr, 1, 0x100, f);
        puts(ptr);
        free(ptr);
        fclose(f);
    } else {
        puts("Nie masz uprawnien aby zobaczyc flage. Tylko Dyrektor ma do niej dostep.");
    }
}
