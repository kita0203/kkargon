#define _GNU_SOURCE 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>
#include "argon2.h"
#include "core.h"

#define ever ;;i++

enum {block_size = 16};
enum {rounds = 10};
#define T_COST_DEF 3
#define LOG_M_COST_DEF 12 /* 2^12 = 4 MiB */
#define LANES_DEF 1
#define THREADS_DEF 1
#define OUTLEN_DEF 32
#define MAX_PASS_LEN 128

#define UNUSED_PARAMETER(x) (void)(x)

void cryptb (unsigned char *block, unsigned char *left, unsigned char *right, unsigned char *cf, unsigned char *new_left)
{
    int i, j;
    for (i = 0; i < rounds; i++) {
        memcpy(left, block, block_size / 2);
        memcpy(right, block + block_size / 2, block_size / 2);
        cf = f(left, block_size / 2);/*ここをargon2に変える*/
        for (j = 0; j < block_size / 2; j++) new_left[j] = right[j] ^ cf[j];
        memcpy(right, left, block_size / 2);
        memcpy(left, new_left, block_size / 2);
        memcpy(block, left, block_size / 2);
        memcpy(block + block_size / 2, right, block_size / 2);
        if (cf) free(cf);
    }
}
void decrypt(unsigned char *block,  unsigned char *left, unsigned char *right, unsigned char *cf, unsigned char *new_left)
{
    int i, j;
    for (i = rounds - 1; i >= 0; i--) {
        memcpy(left, block, block_size / 2);
        memcpy(right, block + block_size / 2, block_size / 2);
        cf = f(right, block_size / 2);/*ここをargon2に変える*/
        for (j = 0; j < block_size / 2; j++) new_left[j] = left[j] ^ cf[j];
        memcpy(left, right, block_size / 2);
        memcpy(right, new_left, block_size / 2);
        memcpy(block, left, block_size / 2);
        memcpy(block + block_size / 2, right, block_size / 2);
        if (cf) free(cf);
    }
}



unsigned char *f(unsigned char *block, int size)
{
    int i;
    unsigned char *cip = calloc(size, sizeof(unsigned char));
    for (i = 0; i < size; i++) {
        cip[i] = block[i] ^ key[i];/*鍵とSBOXの部分がfeistelのラウンド関数部分→ここをargon2にかえる→ここの部分がargon2の入力部分（メッセージ）*/
    }
    
     return cip;
}


void free_arr(unsigned char **a)
{
    if (a && *a) {
        free(*a);
        *a = NULL;
    }
}


int main(int argc, char *argv[])
{
    FILE *fp; // FILE型構造体
	char fname[] = "test.txt";
 
	fp = fopen(fname, "r"); // ファイルを開く。失敗するとNULLを返す。
	if(fp == NULL) {
		printf("%s file not open!\n", fname);
		return -1;
	} else {
		printf("%s file opened!\n", fname);
	}

    //↑の奴の位置を変える。


    if (argc <= 2) {
        if (argc  < 2) {
            printf("Too few arguments\n");
            exit(1);
        }
        if (!(strcmp(argv[1], "-help")) || !(strcmp(argv[1], "-h"))) execlp("cat", "cat", "HELP", NULL);
        else {
            printf("Bad arguments\n");
            exit(1);
        }
    }

    int mode = 0; 
    if (!(strcmp(argv[1], "-e")) || !(strcmp(argv[1], "-encrypt"))) {
        mode = 0;
    } else if (!(strcmp(argv[1], "-d")) || !(strcmp(argv[1], "-decrypt"))) {
            mode = 1;
    } else {
        printf("Bad arguments\n");
        exit(1);
    }
    unsigned char *block = calloc(block_size, sizeof(unsigned char));
    unsigned char *left = calloc(block_size / 2, sizeof(unsigned char));
    unsigned char *right = calloc(block_size / 2, sizeof(unsigned char));
    unsigned char *cf = NULL;
    unsigned char *new_left = calloc(block_size / 2, sizeof(unsigned char));
    unsigned char *p = NULL;
    char *str;
    int i, rc = 0, wc = 0, last_rc = 0;
    long x = 0;
    int fd1 = open(argv[2], O_RDONLY), fd2 = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd1 == -1 || fd2 == -1) {
        printf("Bad file name\n");
        exit(1);
    }
    char c[3], *eptr = NULL;
    str = getstr();
    
    
    memset(block, '\n', block_size);/*いらないかも*/
    p = block;
    while ((rc = read(fd1, p, block_size - rc)) > 0) {
            p+=rc;
            if (rc == block_size) {
                if (mode == 0) {
                    cryptb(block,  left, right, cf, new_left);
                } else decrypt(block, left, right, cf, new_left);
                p = block;
                wc =0;
                while ((wc = write(fd2, p, block_size - wc)) > 0) {
                    p+=wc;
                    if (wc == block_size) {
                        p = block;
                        rc = 0;
                        memset(block, '\n', block_size);
                        break;
                    }
                }
            }
            last_rc = rc; 
    }
    if (last_rc != 0) {
        if (mode == 0) {
            cryptb(block,  left, right, cf, new_left);
        } else decrypt(block,  left, right, cf, new_left);
        p = block;
        wc = 0;
        while ((wc = write(fd2, p, block_size - wc)) > 0) {   
            p+=wc;
            if (wc == block_size) break;
        }
    }
    free_arr(&block);
    free_arr(&left);
    free_arr(&right);
    free_arr(&cf);
    free_arr(&new_left);
    if (str) {
        free(str);
        str = NULL;
    }
    close(fd1);
    close(fd2);
    
    return 0;
}