#pragma once
#include <Windows.h>
#include <iostream>

/*
PE Tool
*/
class CPEUtil
{
public:
	CPEUtil();
	~CPEUtil();

	/*
	load a file
	*/
	BOOL LoadFile(const char* path);
	void PrintPEHeader();
	void PrintPEOptionalHeader();
	void PrintSectionHeaders(); 

private:
	char* fileBuff;		
	DWORD fileSize;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER pSectionFirstHeader;

	/*
	init pe file info
	*/
	BOOL InitPEInfo();

};