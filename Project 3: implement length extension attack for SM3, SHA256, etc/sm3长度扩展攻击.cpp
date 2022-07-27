#include <string.h>
#include <stdio.h>
#include "sm3.h"
#include <iostream>
using namespace std;

//ʮ������תΪunsigned char
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
	//	������չ���� 
	// 	��֪��ϢM�Ĺ�ϣֵ��M�ĳ��� ������Ϣ�������ʵ�ֳ�����չ����
	// 	�����������£�
	// 	   1.����ϢM�Ĺ�ϣֵ��Ϊ��ʼIV���� ������Ϣx��Ϊ���� ���������µĹ�ϣֵ
	//	   2.���ı��ʼIV���� ��M||len��M��||X��Ϊ���� ���������µĹ�ϣֵ
	// 	   3.�Ƚ�1 2 ��������µĹ�ϣֵ �ᷢ���м����������ͬ
	// 	   

	unsigned char output[32];
	int i;
	//����һ 
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


	//�����
	
		unsigned char attack[256] = "length_extension_attack";
		int ilen = 64;  //��Ҫ��len(M||len(padding))
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