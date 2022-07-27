/*
* int 4 bytes and 32 bits
* the longest length of message is 2^32 - 1 bits，
* the length of message mod 8 ≡ 0
*/

#ifndef _SM3_H_
#define _SM3_H_

/*
* SM3算法产生的哈希值大小（单位：字节）
*/
#define SM3_HASH_SIZE 32 

/*
* SM3上下文
*/
typedef struct SM3Context
{
	unsigned int intermediateHash[SM3_HASH_SIZE / 4];
	unsigned char messageBlock[64];
} SM3Context;

/*
* SM3计算函数
*/

unsigned char* SM3Calc(const unsigned char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);

/*
为长度扩展攻击做准备
*/
unsigned int* ReverseMessage(unsigned int* message);

static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)

#endif // _SM3_H_