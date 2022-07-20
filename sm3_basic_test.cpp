#include <string.h>
#include <stdio.h>
#include "sm3.h"
#include <iostream>
using namespace std;

int main0( )
{
	unsigned char input[256] = "abc";
	int ilen = 3;
	unsigned char output[32];
	int i;
	// ctx;
	cout << "Demo:" << endl<<endl;
		
	SM3Calc(input, ilen, output);
	cout << "Hash of " << input << ":" << endl;
	
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}

	cout << endl<<endl;

	unsigned char input2[256] = "202000141016";
	int ilen2 = 12;
	unsigned char output2[32];
	int i2;
	// ctx;

	SM3Calc(input2, ilen2, output2);
	cout << "Hash of " << input2 << ":" << endl;
	for (i2 = 0; i2 < 32; i2++)
	{
		printf("%02x", output2[i2]);
		if (((i2 + 1) % 4) == 0) printf(" ");
	}
	cout << endl;

	return 0;
}