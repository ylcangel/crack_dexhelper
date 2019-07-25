/**
 * Author: sp00f
 * 版权属于我个人所有，你可以转载，但需要标明出处
 * 此文档只用于学习交流目的，用于其他目的本人概不负责
 * 安全既是攻防，希望我所作能对防守的一方提供帮助
 * 各个厂商思路同中有异，我逆向分析仅站在学习者和探测加固强度角度进行，没有针对任何特定厂商
 * 我逆向的版本不是最新版本，甚至我都不知道是哪个版本，请大家多吸取精华，抛弃糟粕
 * 你可以吐槽我，不过还是希望尊重我的辛苦成果，有不对的地方，可以指出，大家互相探讨
 * 对于逆向我也是个小学生，水平有限，还请大佬们一笑而过
 *
*/

#include "decrypt.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#define LOBYTE(x)   (*((unsigned char*)&(x)))   // low byte

static int decrypt(int foff, unsigned char* buf, int buflen) {
	// 解密算法 foff文件偏移小于0x20000用rc4和异或，大于直接异或0xac
	// 这里的rc4算法感觉稍有不同， 它密钥固定， 其次好像没有用到临时向量T
	int v3; // r6@2
	unsigned char* kbox; // r8@5
	int v6; // r4@7
	int j; // lr@7
	int i; // r5@7
	int tmp; // r9@8
	int k; // r12@8
	int v11; // lr@11
	int v12; // r5@11
	int v13; // r4@11
	unsigned char v14; // r12@13
	unsigned char* bufp; // lr@14
	unsigned char v16; // r0@15
	int v17; // r8@15
	int v18; // t1@15
	unsigned char* curr_bufp; // r1@19
	unsigned char sbox[256]; // [sp+4h] [bp-124h]@6

	unsigned char key[16] = {0x66,0x97,0x6C,0xE8, 0x6D, 0x46, 0x38,
					0xB0, 0x9, 0x5A, 0xA5, 0xD7, 0xF, 0xCB, 0x9A, 0xA0};

	if (foff >= 0x20000) {
		v3 = 0;
	} else { // foff < 0x20000

		v3 = 0x20000 - foff;
		if (0x20000 - foff >= buflen)
			v3 = buflen;

		buflen -= v3; // 这个变量后面没用

		if (v3 > 0) { // 像rc4
			kbox = key; //
		    for(int i = 0; i < 256; i++)//初始化算法
		    {
		        sbox[i] = i;
		    }

			v6 = 0;
			j = 0;
			i = 0;

			do { // 交换256次
				tmp = sbox[i];
				k = kbox[v6++];
				j +=  (k + tmp);
				j = j %256;
				if (v6 > 15)
					v6 = 0;

				sbox[i++] = sbox[j];
				sbox[j] = tmp;
			} while (i != 256);

			v11 = 0;
			LOBYTE(v12) = 0;
			LOBYTE(v13) = 0;

			while (v11 != foff) { // 在交换foff次
				++v11;
				v13 =  (v13 + 1) % 256;
				v14 = sbox[v13];
				v12 = (v12 + v14) % 256;
				sbox[v13] = sbox[v12];
				sbox[v12] = v14;

			}

			//前面都是在交换
			bufp = buf;

			do { // 此处开始真正解密
				v13 = (unsigned char) (v13 + 1);
				v16 = sbox[v13];
				v12 =  (unsigned char)(v12 + v16);
				sbox[v13] = sbox[v12];
				sbox[v12] = v16;

				v17 = (unsigned char) sbox[(unsigned char)(v16 + sbox[v13])];

				v18 = *(char*) bufp++;

				foff = v17 ^ v18;

				*(char*) (bufp - 1) = v17 ^ v18;

			} while ((int)bufp != ((int)buf + v3));

		}
	}

	if (buflen > 0) { // 如果foff > 0x20000也就是128k，直接异或解密
		curr_bufp =  buf + v3;
		foff = (int) curr_bufp; // buf 起始地址

		do {
			*(unsigned char*) curr_bufp++ ^= 0xACu;
		} while ((int)curr_bufp - foff < buflen);
	}

	return foff; // 返回起始buf地址
}


/**
 **注意请在Linux下跑
 **我之前在windows mingw 跑 read会出现问题
 **程序只是随便写写
 **没有优化，因为最初在windows下编写的代码
 **所以没有用mmap
 **对程序处理出错就exit，当时也是为了省事
 **你可以随意优化该段程序
 */
void decrypt_classes0jar(const char* file, const char* ofile) {
	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open file failed!");
		exit(1);
	}

	int fid = open(ofile, O_WRONLY | O_CREAT );
	if( fid < 0) {
		perror("creat zip file failed!");
		exit(1);
	}


	struct stat statbuf;
	stat(file, &statbuf);
	int size = statbuf.st_size;

	printf("file size = %x\n", size);

	char zheader[0x100];
	char zname[0x100];
	char zex[0x100];
	int loop_size = 1024;

	char* filebuf = (char*) malloc(size);
	if (!filebuf) {
		perror("malloc filebuf failed!");
		exit(-1);
	}

	memset(filebuf, 0, size);
	memset(zheader, 0, 0x100);
	memset(zname, 0, 0x100);
	memset(zex, 0, 0x100);

	int zheader_size = sizeof(struct ZipFileHeader);

	off_t off = lseek(fd, 0, SEEK_SET);
	printf("off = %x\n", off);
	ssize_t len = read(fd, zheader, zheader_size);
	printf("len = %lx\n", len);
	size_t f_off = decrypt(0, (unsigned char*)zheader, zheader_size);
	memcpy(filebuf, zheader, zheader_size);

	struct ZipFileHeader* zip_header = (struct ZipFileHeader*) zheader;

	int first_zipentry_off = (sizeof(struct ZipFileHeader) + zip_header->compress_size +
			zip_header->file_name_length + zip_header->extra_field_len);

	int buf2_size = size - first_zipentry_off;
	printf("first zipentry size = %x, buf2 size = %x\n", first_zipentry_off, buf2_size);

	char* buf1 =  (char*) malloc(loop_size);
	if (!buf1) {
		perror("malloc buf1 failed!");
		exit(-1);
	}

	char* buf2 = (char*) malloc(buf2_size);
	if (!buf2) {
		perror("malloc buf2 failed!");
		exit(-1);
	}

	memset(buf1, 0, loop_size);
	memset(buf2, 0, buf2_size);

	off = lseek(fd, 0, SEEK_CUR);
	printf("off = %x\n", off);
	len = read(fd, zname, zip_header->file_name_length);
	printf("len = %lx\n", len);
	f_off = decrypt(0, (unsigned char*)zname, zip_header->file_name_length);
	memcpy(filebuf + off, zname, zip_header->file_name_length);

	off = lseek(fd, 0, SEEK_CUR);
	printf("off = %x\n", off);
	len = read(fd, zex, zip_header->extra_field_len);
	printf("len = %lx\n", len);
	f_off = decrypt(0, (unsigned char*)zex, zip_header->extra_field_len);
	memcpy(filebuf + off, zex, zip_header->extra_field_len);

	off = lseek(fd, 0, SEEK_CUR);
	printf("off = %x\n", off);

	while (off < first_zipentry_off) {
		int max_size = loop_size;
		int last_size = first_zipentry_off - off;
		if ( last_size < loop_size ) {
			max_size = last_size;
		}

		printf("max size = %x\n", max_size);

		len = read(fd, buf1, max_size);
		printf("len = %lx\n", len);
		f_off = decrypt(off, (unsigned char*)buf1, max_size);

		memcpy(filebuf + off, buf1, max_size);
		memset(buf1, 0, loop_size);


		off = lseek(fd, 0, SEEK_CUR);
		printf("off = %x\n", off);

	}


	off = lseek(fd, 0, SEEK_CUR);
	printf("off = %x\n", off);


	len = read(fd, buf2, buf2_size);
	printf("len = %x\n", len);
	f_off = decrypt(off, (unsigned char*)buf2, buf2_size);


	printf("buf2 size = %x, off = %x\n", buf2_size, off);
	memcpy(filebuf + off, buf2, buf2_size);

	ssize_t wlen = write(fid, filebuf, size);
	printf("wlen = %x\n", wlen);

	free(buf1);
	free(buf2);
	free(filebuf);

	buf1 = NULL;
	buf2 = NULL;
	filebuf = NULL;

	close(fd);
	close(fid);
}
