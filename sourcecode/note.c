#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <openssl/aes.h>

const char username[] = "Mai";
const char passwd[] = "1202";
unsigned char *key;
unsigned char *secret;
unsigned char* note_list[8];
unsigned int size_list[8];

void encrypt(const unsigned char *plaintext, int size, unsigned char *ciphertext) {
    AES_KEY aesKey;

    AES_set_encrypt_key(key, 128, &aesKey);
    int numBlocks = (size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int padding = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int padded_len = size + padding;

    unsigned char padded_plaintext[padded_len];
    memcpy(padded_plaintext, plaintext, size);
    memset(padded_plaintext + size, padding, padding); // PKCS#5

    for (int i = 0; i < numBlocks; i++) {
        AES_encrypt(padded_plaintext + (i * AES_BLOCK_SIZE), ciphertext + (i * AES_BLOCK_SIZE), &aesKey);
    }
}

void decrypt(const unsigned char *ciphertext, int size, unsigned char *plaintext) {
    AES_KEY aesKey;

    AES_set_decrypt_key(key, 128, &aesKey);
    int numBlocks = (size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    for (int i = 0; i < numBlocks; i++) {
        AES_decrypt(ciphertext + (i * AES_BLOCK_SIZE), plaintext + (i * AES_BLOCK_SIZE), &aesKey);
    }
}

void init_key() {
    unsigned char *flag = malloc(0x50);
    int fd;
    int flag_len;

    if ((key = (unsigned char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        _exit(1);
    }
    if ((secret = (unsigned char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        _exit(1);
    }

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        _exit(1);
    }
    if (read(fd, key, 0x10) != 0x10) {
        _exit(1);
    }
    close(fd);

    fd = open("/flag", O_RDONLY);
    if (fd < 0) {
        _exit(1);
    }
    if ((flag_len = read(fd, flag, 0x50)) <= 0) {
        _exit(1);
    }
    close(fd);

    encrypt(flag, flag_len, secret);
    memset(flag, '\x00', 0x50);
    free(flag);

    if (mprotect(key, 0x1000, PROT_READ) == -1) {
        _exit(1);
    }
    if (mprotect(secret, 0x1000, PROT_READ) == -1) {
        _exit(1);
    }
}

void banner() {
    puts("#    #  ####  ##### ######");
    puts("##   # #    #   #   #");
    puts("# #  # #    #   #   #####");
    puts("#  # # #    #   #   #");
    puts("#   ## #    #   #   #");
    puts("#    #  ####    #   ######");
}

void sandbox() {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    struct sock_filter sfi[] = {
        {0x20, 0x00, 0x00, 0x00000004},
        {0x15, 0x00, 0x04, 0xc000003e},
        {0x20, 0x00, 0x00, 0x00000000},
        {0x15, 0x03, 0x00, 0x00000000},
        {0x15, 0x02, 0x00, 0x00000001},
        {0x15, 0x01, 0x00, 0x000000e7},
        {0x06, 0x00, 0x00, 0x00000000},
        {0x06, 0x00, 0x00, 0x7fff0000},
    };
    struct sock_fprog sfp = {8, sfi};
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sfp);
}

void init_io() {
    setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
    banner();
    sandbox();
}

int read_int() {
    char buf[0x10];

    read(0, buf, 0x10);
    return atoi(buf);
}

void welcome() {
    char buf[12];

    memset(buf, '\x00', sizeof(buf));
    puts("Welcome to the note encryption system");
    printf("Username: ");
    read(0, buf, 0x100);
    if (strncmp(buf, username, strlen(username))) {
        puts("User unauthorized");
        _exit(1);
    }
    printf("Hello %s", buf);

    printf("Password: ");
    read(0, buf, 0x100);
    if (strncmp(buf, passwd, strlen(passwd))) {
        puts("Password error");
        _exit(1);
    }
    puts("Login successful");
}

void menu() {
    puts("\n[1] Add note");
    puts("[2] View note");
    puts("[3] Delete note");
    puts("[4] Exit");
    printf("choice: ");
}


void add() {
    unsigned int size;
    unsigned int idx;
    unsigned char *plaintext;
    unsigned char *ciphertext;

    printf("index: ");
    idx = read_int();
    if (idx >= 8) {
        puts("Invalid index");
        return;  // optional
    }

    printf("size: ");
    size = read_int();
    if (size > 0x60) {
        puts("Invalid size");
        return;
    }

    plaintext = malloc(size);
    memset(plaintext, '\x00', size);
    printf("content: ");
    for (int i = 0; i <= size; i++) {
        read(0, plaintext + i, 1);
        if (*(plaintext + i) == '\n') {
            *(plaintext + i) = '\x00';
            break;
        }
    }

    ciphertext = malloc(((size + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
    encrypt(plaintext, size, ciphertext);
    free(plaintext);
    note_list[idx] = ciphertext;
    size_list[idx] = size;
}

void view() {
    unsigned int idx;
    unsigned char *plaintext;

    printf("index: ");
    idx = read_int();
    if (idx >= 8 || !note_list[idx]) {
        puts("Invalid index");
        return;
    }
    plaintext = malloc(((size_list[idx] + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
    if (size_list[idx]) {
        memset(plaintext, '\x00', size_list[idx]);
    } else {
        *plaintext = '\x00';
    }
    decrypt(note_list[idx], size_list[idx], plaintext);
    printf(plaintext);
    free(plaintext);
}

void del() {
    unsigned idx;

    printf("index: ");
    idx = read_int();
    if (idx >= 8 || !note_list[idx]) {
        puts("Invalid index");
        return;
    }
    free(note_list[idx]);

    __asm("nop");   // nop * 0x1C
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
    __asm("nop");
}

int main() {
    init_key();
    init_io();
    welcome();

    while (1) {
        int choice;
        menu();
        choice = read_int();
        switch(choice) {
            case 1:
                add();
                break;
            case 2:
                view();
                break;
            case 3:
                del();
                break;
            default:
                _exit(0);
        }
    }
}
