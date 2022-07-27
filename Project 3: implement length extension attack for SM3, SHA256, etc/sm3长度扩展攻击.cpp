#include <string.h>
#include <stdio.h>
#include "sm3.h"
#include <iostream>
using namespace std;

//十六进制转为unsigned char
int hexstr_to_byte(const   char* pInHexString, int   nInLen, unsigned char* pOut)
{
	if (pInHexString == NULL || pOut == NULL || (nInLen % 2))
	{
		return   -1;
	}
	int   nIndex = 0;
	unsigned char   nData = 0;
	unsigned char   nOut = 0;
	char   Temp[2];

	for (int i = 0; i < nInLen; i += 2)
	{
		Temp[0] = pInHexString[i];
		Temp[1] = pInHexString[i + 1];

		for (int j = 0; j < 2; ++j)
		{
			switch (Temp[j])
			{
			case   '0':
			case   '1':
			case   '2':
			case   '3':
			case   '4':
			case   '5':
			case   '6':
			case   '7':
			case   '8':
			case   '9':
				nData = Temp[j] - '0';
				nOut += nData << ((1 - j) * 4);
				break;
			case   'A':
			case   'B':
			case   'C':
			case   'D':
			case   'E':
			case   'F':
				nData = Temp[j] - 'A' + 10;
				nOut += nData << ((1 - j) * 4);
				break;
			case   'a':
			case   'b':
			case   'c':
			case   'd':
			case   'e':
			case   'f':
				nData = Temp[j] - 'a' + 10;
				nOut += nData << ((1 - j) * 4);
				break;
			default:
				return   -1;
			}
		}
		pOut[nIndex++] = nOut;
		nOut = 0;
	}

	return   0;
}

int main()
{
	//	长度扩展攻击 
	// 	已知消息M的哈希值及M的长度 进行消息的填充以实现长度扩展攻击
	// 	具体做法如下：
	// 	   1.将消息M的哈希值作为初始IV输入 任意消息x作为明文 求此种情况下的哈希值
	//	   2.不改变初始IV输入 将M||len（M）||X作为明文 求此种情况下的哈希值
	// 	   3.比较1 2 两种情况下的哈希值 会发现中间情况存在相同
	// 	   

	unsigned char output[32];
	int i;
	//步骤一 
		//unsigned char input[256] = "Wang Lei 202000141016";
		////memset(input + 21, '1', 16);
		////cout << input << endl;
		//unsigned int bitLen=21*8;
		//if (IsLittleEndian())
		//	ReverseMessage(&bitLen);
		//input[21] = 0x80;
		//memset(input + 21 + 1, 0, 64 - 21 - 1 - 8 + 4);
		//memcpy(input + 64 - 4, &bitLen, 4);
		////cout << input << endl;
		//unsigned char attack[256] = "length_extension_attack";
		////int ilen = 23;
		//memcpy(input + 64, attack, 23);
		//int ilen = 87;
		//cout << input<<endl;

		//SM3Calc(input, ilen, output);


	//步骤二
	
		unsigned char attack[256] = "length_extension_attack";
		int ilen = 64;  //需要加len(M||len(padding))
		unsigned int bitLen=87*8;
		if (IsLittleEndian())
			ReverseMessage(&bitLen);
		attack[23] = 0x80;
		memset(attack + 23 + 1, 0, 64 - 23 - 1 - 8 + 4);
		memcpy(attack + 64 - 4, &bitLen, 4);
		cout << "message:" << endl << attack << endl << endl;
		SM3Calc(attack, ilen, output);
	cout << "Hash:" << endl;

	for (i = 0; i < 32; i++)
	{
		printf("%02X", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	cout << endl;
	


	return 0;
}