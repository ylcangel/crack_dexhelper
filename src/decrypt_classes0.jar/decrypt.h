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

#ifndef DECRYPT_H_
#define DECRYPT_H_


typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

struct ZipFileHeader {
	uint32_t magic;
	uint16_t version;
	uint16_t flags;
	uint16_t compression_method;
	uint16_t lastmodtime;
	uint16_t lastmoddate;
	uint32_t crc32_cs;
	uint32_t compress_size;
	uint32_t file_size;
	uint16_t file_name_length;
	uint16_t extra_field_len; // 扩展区长度
} __attribute__((packed));

#ifdef	__cplusplus
extern "C" {
#endif

void decrypt_classes0jar(const char* sfile, const char* dfile);

#ifdef	__cplusplus
}
#endif

#endif /* DECRYPT_H_ */
