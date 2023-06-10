#include <Windows.h>
#include <iostream>
#include "CPEUtil.h"

int main()
{
	/*
	// dosͷ
	PIMAGE_DOS_HEADER pDosHeader{ 0 };

	// peͷ
	PIMAGE_NT_HEADERS pNtHeaders{ 0 };

	// ��׼peͷ
	PIMAGE_FILE_HEADER pFileHeader{ 0 };

    // ��ѡpeͷ
	PIMAGE_OPTIONAL_HEADER pOptionalHeader{ 0 };

	// ���ļ�
	HANDLE hFile = CreateFileA("IF.exe", GENERIC_READ, FILE_SHARE_READ, NULL, 
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	// �ļ���С
	DWORD fileSize = GetFileSize(hFile, NULL);

	// ��ȡ�ļ�������
	char* fileBuff = new char[fileSize];

	// ʵ�ʶ�ȡ��С
	DWORD realRead = 0;

	// ��ȡ�ļ�
	BOOL success = ReadFile(hFile, fileBuff, fileSize, &realRead, NULL);
	if (success)
	{
		// ��ȡ�ļ�dosͷ
		pDosHeader = (PIMAGE_DOS_HEADER) fileBuff;

		// �ж��Ƿ�Ϊ��Ч��pe�ļ�
		if (pDosHeader->e_magic != 0x5A4D)
		{
			printf("������Ч��pe�ļ�");
			delete[] fileBuff;
			return 0;
		}

		// ��ӡdosͷ��lfanew����ʼλ�õ�peͷ��ƫ����
		printf("e_lfanew=%d\n", pDosHeader->e_lfanew);

		pNtHeaders = (PIMAGE_NT_HEADERS) (fileBuff + pDosHeader->e_lfanew);

		// �ж�PEͷ�Ƿ���Ч
		if (pNtHeaders->Signature != 0x4550)
		{
			printf("peͷ���Ϸ�");
			delete[] fileBuff;
			return 0;
		}

		printf("signature:%x\n", pNtHeaders->Signature);
		printf("pNtHeader:%x\n", pNtHeaders);

		// ��ȡ��׼peͷ
		pFileHeader = &pNtHeaders->FileHeader;

		printf("pFileHeader=%d\n", pFileHeader);
		
		// ��һ�ַ�ʽ��ȡ��׼peͷ
		pFileHeader = (PIMAGE_FILE_HEADER) ((DWORD) pNtHeaders + 4);
		printf("pFileHeader=%d\n", pFileHeader);

		printf("pFileHeader->Machine=%x\n", pFileHeader->Machine);
		printf("pFileHeader->Characteristics=%x\n", pFileHeader->Characteristics);
		printf("pFileHeader->NumberOfSections=%x\n", pFileHeader->NumberOfSections);
		printf("pFileHeader->SizeOfOptionalHeader=%x\n", pFileHeader->SizeOfOptionalHeader);

		// ��ȡ��ѡpeͷ
		pOptionalHeader = &pNtHeaders->OptionalHeader;

		// ��һ�ַ�ʽ��ȡpeͷ
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
		printf("����PE�ļ�ʧ��\n");
	}
	cPEUtil.PrintPEHeader();
	cPEUtil.PrintPEOptionalHeader();
	cPEUtil.PrintSectionHeaders();

	return 0;
}