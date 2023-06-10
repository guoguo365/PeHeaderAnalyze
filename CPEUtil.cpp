#include "CPEUtil.h"

CPEUtil::CPEUtil()
{
	CPEUtil::fileBuff = NULL;
	CPEUtil::fileSize = NULL;
	CPEUtil::pDosHeader = NULL;
	CPEUtil::pNtHeaders = NULL;
	CPEUtil::pFileHeader = NULL;
	CPEUtil::pOptionalHeader = NULL;
	CPEUtil::pSectionFirstHeader = NULL;
}

CPEUtil::~CPEUtil()
{
	if (CPEUtil::fileBuff)
	{
		delete[] fileBuff;
		fileBuff = NULL;
	}
}

BOOL CPEUtil::LoadFile(const char* path)
{
	// 打开文件
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == 0)
	{
		return FALSE;
	}

	// 文件大小
	CPEUtil::fileSize = GetFileSize(hFile, NULL);

	// 读取文件缓冲区
	CPEUtil::fileBuff = new char[fileSize] {0};

	// 实际读取大小
	DWORD realReadBytes = 0;

	// 读取文件
	if (!ReadFile(hFile, fileBuff, fileSize, &realReadBytes, NULL))
	{
		return FALSE;
	}

	// 初始化PE
	if (!InitPEInfo())
	{
		return FALSE;
	}

	// 关闭文件句柄
	CloseHandle(hFile);
	return TRUE;
}

BOOL CPEUtil::InitPEInfo()
{
	// 获取文件dos头
	CPEUtil::pDosHeader = (PIMAGE_DOS_HEADER) CPEUtil::fileBuff;

	// 判断是否为有效的pe文件
	if (CPEUtil::pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	// 获取NT头
	CPEUtil::pNtHeaders = (PIMAGE_NT_HEADERS) (fileBuff + CPEUtil::pDosHeader->e_lfanew);

	// 判断PE头是否有效
	if (CPEUtil::pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	// 获取标准pe头
	CPEUtil::pFileHeader = &CPEUtil::pNtHeaders->FileHeader;

	// 获取可选pe头
	CPEUtil::pOptionalHeader = &CPEUtil::pNtHeaders->OptionalHeader;

	return TRUE;
}

void CPEUtil::PrintPEHeader()
{
	if (!CPEUtil::pFileHeader) {
		printf("PE标准头错误，无法打开\n");
		return;
	}
	printf("====================PE标准头====================\n");
	printf("pFileHeader->Machine=%x\n", pFileHeader->Machine);
	printf("pFileHeader->Characteristics=%x\n", pFileHeader->Characteristics);
	printf("pFileHeader->NumberOfSections=%x\n", pFileHeader->NumberOfSections);
	printf("pFileHeader->SizeOfOptionalHeader=%x\n", pFileHeader->SizeOfOptionalHeader);
}

void CPEUtil::PrintPEOptionalHeader()
{
	if (!CPEUtil::pOptionalHeader)
	{
		printf("PE扩展头错误，无法打开\n");
		return;
	}
	printf("====================PE扩展头====================\n");
	printf("pOptionalHeader->AddressOfEntryPoint=%x\n", pOptionalHeader->AddressOfEntryPoint);
	printf("pOptionalHeader->ImageBase=%x\n", pOptionalHeader->ImageBase);
	printf("pOptionalHeader->SectionAlignment=%x\n", pOptionalHeader->SectionAlignment);
	printf("pOptionalHeader->FileAlignment=%x\n", pOptionalHeader->FileAlignment);
	printf("pOptionalHeader->SizeOfCode=%x\n", pOptionalHeader->SizeOfCode);
	printf("pOptionalHeader->SizeOfHeaders=%x\n", pOptionalHeader->SizeOfHeaders);
}

void CPEUtil::PrintSectionHeaders()
{
	pSectionFirstHeader = IMAGE_FIRST_SECTION(CPEUtil::pNtHeaders);
	printf("====================PE段头====================\n");
	printf("Secion number:%d\n", CPEUtil::pFileHeader->NumberOfSections);

	for (int i = 0; i < CPEUtil::pFileHeader->NumberOfSections; i++)
	{
		char name[9]{ 0 };
		memcpy(name, (CPEUtil::pSectionFirstHeader + i)->Name, 8);
		printf("Section name:%s\n", name);
	}
	
}