#include <string>
#include <iostream>
#include <vector>
#include <regex>
#include <windows.h>
#include <stdio.h>
#include "getopt.h"
using namespace std;

char szAccountFile[MAX_PATH] = "c:\\Accounts.tdat";
char szInstalledPath[MAX_PATH] = { 0 };
char szOutputFile[MAX_PATH] = { 0 };

void showHelp();
bool parseArguments(int argc, char* argv[]);
void readAccountFile(char* szFilePath);
string decoder(bool bVersion6, string strHash);

int main(int argc, char* argv[])
{
	if (!parseArguments(argc, argv))
	{
		showHelp();
	};

	readAccountFile(szAccountFile);

	decoder(true, "3AAE7495689867B762ED4405");

	return 1;
}

// 核心解密算法
string decoder(bool bVersion6, string strHash)
{
	string strPlainPassword;
	// 第一步：定义不同版本的秘钥
	vector<int> a(8), b, c;
	int fc = 0;
	if (bVersion6)
	{
		a[0] = '~';
		a[1] = 'd';
		a[2] = 'r';
		a[3] = 'a';
		a[4] = 'G';
		a[5] = 'o';
		a[6] = 'n';
		a[7] = '~';
		fc = 0x5A;
	}
	else
	{
		a[0] = '~';
		a[1] = 'F';
		a[2] = '@';
		a[3] = '7';
		a[4] = '%';
		a[5] = 'm';
		a[6] = '$';
		a[7] = '~';
		fc = 0x71;
	}

	// 第二步：以字节为单位将16进制密文转成10进制
	int temp = 0;
	string section;
	for (UINT i = 0; i < strHash.length(); i += 2)
	{
		sscanf_s((strHash.substr(i, 2)).c_str(), "%x", &temp);
		b.push_back(temp);
	}

	// 第三步：将第一个元素替换成与指定数异或后的结果
	c = b;
	c[0] = c[0] ^ fc;

	 // 第四步：不断扩容拷贝自身
	while (b.size() > a.size())
	{
		vector<int> expendA(2 * a.size());
		for (UINT i = 0; i < a.size(); i++)
		{
			expendA[i] = a[i];
			expendA[i + a.size()] = a[i];
		}
		a = expendA;
	}

	
	vector<int> d(b.size());
	for (UINT i = 1; i < b.size(); i++)
	{
		d[i - 1] = b[i] ^ a[i - 1];

	}

	vector<int> e(d.size());
	for (UINT i = 0; i < d.size() - 1; i++)
	{
		if (d[i] - c[i] < 0)
		{
			e[i] = d[i] + 255 - c[i];
		}

		else
		{
			e[i] = d[i] - c[i];
		}
		strPlainPassword += (char)e[i];
	}

	return strPlainPassword;
}

void readAccountFile(char* szFilePath)
{
	HANDLE hFile = CreateFile(szFilePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		cout << "open file error!\n";
		CloseHandle(hFile);
		exit(0);
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	byte* buffer = new byte[dwFileSize];
	ZeroMemory(buffer, dwFileSize);
	DWORD dwBytesRead = 0;
	ReadFile(hFile, buffer, dwFileSize, &dwBytesRead, NULL);
	CloseHandle(hFile);

	// 判断foxmail版本，首字节为0xD0，则为6.X版本
	bool bVersion6 = false;
	if (0xD0 == buffer[0])
	{
		bVersion6 = true;
	}

	// 由于byte数组中存在截断字符，不能直接转char类型
	string strText;
	for (UINT i = 0; i < dwFileSize; ++i)
	{
		if (buffer[i] > 0x20 && buffer[i] < 0x7f && buffer[i] != 0x3d)
		{
			strText += (char)buffer[i];
		}
	}

	// 使用正则匹配
	regex reg("MailAddress(.*)MailListFont.*POP3Password(.*)POP3Port");
	cmatch mt;
	regex_search(strText.c_str(), mt, reg);
	for (size_t i = 1; i < mt.size(); ++i)
	{
		cout << mt.str(i);
	}

	int nStartIndex = strText.find("MailAddress", 0);
	int nEndIndex = strText.find("MailListFont", 0);
	string strEmail = strText.substr(nStartIndex + 11, nEndIndex - nStartIndex -11);
	// 读取密文密码
	nStartIndex = strText.find("POP3Password", 0);
	nEndIndex = strText.find("POP3Port", 0);
	string strHash = strText.substr(nStartIndex + 12, nEndIndex - nStartIndex - 12);
	//cout << strHash;

	delete[] buffer;
}

void showHelp()
{
	cout << "FoxmailDump 1.0  Dump Local Foxmail Passwords\n";
	cout << "https://github.com/tuboshu/FoxmailDump\n\n";
	cout << "Usage: FoxmailDump <-f file|-p path> [Options]\n";
	cout << "\nOptions:\n";
	cout << "  -f <file>\tFoxmail account file\n";
	cout << "\t\tAccount.stg(version<7.0)|Accounts.tdat(version<7.2)\n";
	cout << "  -p <path>\tAutomatic search account files in specific path\n";
	cout << "  -o <file>\tOutput results to the given filename\n";
	cout << "  -h\t\tThis cruft\n";
	cout << "\nExamples:\n";
	cout << "  FoxmailDump.exe -f Account.cfg\n";
	cout << "  FoxmailDump.exe -p \"D:\\Foxmail 7.2\" -o pass.txt\n";

}

bool parseArguments(int argc, char* argv[])
{
	if (1 == argc)
	{
		return false;
	}
	// 后面带冒号的是开关选项，不带冒号是参数选项
	// optarg全局变量为参数选项的具体参数值
	int option = 0;
	while ((option = getopt(argc, argv, "hf:p:o:")) != EOF)
	{
		switch (option)
		{
		case 'h':
			showHelp();
			break;
		case 'f':
			strcpy_s(szAccountFile, optarg);
			break;
		case 'p':
			strcpy_s(szInstalledPath, optarg);
			break;
		case 'o':
			strcpy_s(szOutputFile, optarg);
			break;
		default:
			return false;
		}
	}

	return true;
}