#include <Windows.h>
#include <iostream>
#include "CPEUtil.h"

int main()
{
	/*
	// dos头
	PIMAGE_DOS_HEADER pDosHeader{ 0 };

	// pe头
	PIMAGE_NT_HEADERS pNtHeaders{ 0 };

	// 标准pe头
	PIMAGE_FILE_HEADER pFileHeader{ 0 };

    // 可选pe头
	PIMAGE_OPTIONAL_HEADER pOptionalHeader{ 0 };

	// 打开文件
	HANDLE hFile = CreateFileA("IF.exe", GENERIC_READ, FILE_SHARE_READ, NULL, 
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	// 文件大小
	DWORD fileSize = GetFileSize(hFile, NULL);

	// 读取文件缓冲区
	char* fileBuff = new char[fileSize];

	// 实际读取大小
	DWORD realRead = 0;

	// 读取文件
	BOOL success = ReadFile(hFile, fileBuff, fileSize, &realRead, NULL);
	if (success)
	{
		// 获取文件dos头
		pDosHeader = (PIMAGE_DOS_HEADER) fileBuff;

		// 判断是否为有效的pe文件
		if (pDosHeader->e_magic != 0x5A4D)
		{
			printf("不是有效的pe文件");
			delete[] fileBuff;
			return 0;
		}

		// 打印dos头的lfanew，起始位置到pe头的偏移量
		printf("e_lfanew=%d\n", pDosHeader->e_lfanew);

		pNtHeaders = (PIMAGE_NT_HEADERS) (fileBuff + pDosHeader->e_lfanew);

		// 判断PE头是否有效
		if (pNtHeaders->Signature != 0x4550)
		{
			printf("pe头不合法");
			delete[] fileBuff;
			return 0;
		}

		printf("signature:%x\n", pNtHeaders->Signature);
		printf("pNtHeader:%x\n", pNtHeaders);

		// 获取标准pe头
		pFileHeader = &pNtHeaders->FileHeader;

		printf("pFileHeader=%d\n", pFileHeader);
		
		// 另一种方式获取标准pe头
		pFileHeader = (PIMAGE_FILE_HEADER) ((DWORD) pNtHeaders + 4);
		printf("pFileHeader=%d\n", pFileHeader);

		printf("pFileHeader->Machine=%x\n", pFileHeader->Machine);
		printf("pFileHeader->Characteristics=%x\n", pFileHeader->Characteristics);
		printf("pFileHeader->NumberOfSections=%x\n", pFileHeader->NumberOfSections);
		printf("pFileHeader->SizeOfOptionalHeader=%x\n", pFileHeader->SizeOfOptionalHeader);

		// 获取可选pe头
		pOptionalHeader = &pNtHeaders->OptionalHeader;

		// 另一种方式获取pe头
		pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD) pNtHeaders + 24);
		
		printf("pOptionalHeader->AddressOfEntryPoint=%x\n", pOptionalHeader->AddressOfEntryPoint);
		printf("pOptionalHeader->ImageBase=%x\n", pOptionalHeader->ImageBase);
		printf("pOptionalHeader->SectionAlignment=%x\n", pOptionalHeader->SectionAlignment);
		printf("pOptionalHeader->FileAlignment=%x\n", pOptionalHeader->FileAlignment);
		printf("pOptionalHeader->SizeOfCode=%x\n", pOptionalHeader->SizeOfCode);
		printf("pOptionalHeader->SizeOfHeaders=%x\n", pOptionalHeader->SizeOfHeaders);

	}

	delete[] fileBuff;
	CloseHandle(hFile);
	*/

	CPEUtil cPEUtil;
	if (!cPEUtil.LoadFile("IF.exe"))
	{
		printf("加载PE文件失败\n");
	}
	cPEUtil.PrintPEHeader();
	cPEUtil.PrintPEOptionalHeader();
	cPEUtil.PrintSectionHeaders();

	return 0;
}