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
	// ���ļ�
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == 0)
	{
		return FALSE;
	}

	// �ļ���С
	CPEUtil::fileSize = GetFileSize(hFile, NULL);

	// ��ȡ�ļ�������
	CPEUtil::fileBuff = new char[fileSize] {0};

	// ʵ�ʶ�ȡ��С
	DWORD realReadBytes = 0;

	// ��ȡ�ļ�
	if (!ReadFile(hFile, fileBuff, fileSize, &realReadBytes, NULL))
	{
		return FALSE;
	}

	// ��ʼ��PE
	if (!InitPEInfo())
	{
		return FALSE;
	}

	// �ر��ļ����
	CloseHandle(hFile);
	return TRUE;
}

BOOL CPEUtil::InitPEInfo()
{
	// ��ȡ�ļ�dosͷ
	CPEUtil::pDosHeader = (PIMAGE_DOS_HEADER) CPEUtil::fileBuff;

	// �ж��Ƿ�Ϊ��Ч��pe�ļ�
	if (CPEUtil::pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	// ��ȡNTͷ
	CPEUtil::pNtHeaders = (PIMAGE_NT_HEADERS) (fileBuff + CPEUtil::pDosHeader->e_lfanew);

	// �ж�PEͷ�Ƿ���Ч
	if (CPEUtil::pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	// ��ȡ��׼peͷ
	CPEUtil::pFileHeader = &CPEUtil::pNtHeaders->FileHeader;

	// ��ȡ��ѡpeͷ
	CPEUtil::pOptionalHeader = &CPEUtil::pNtHeaders->OptionalHeader;

	return TRUE;
}

void CPEUtil::PrintPEHeader()
{
	if (!CPEUtil::pFileHeader) {
		printf("PE��׼ͷ�����޷���\n");
		return;
	}
	printf("====================PE��׼ͷ====================\n");
	printf("pFileHeader->Machine=%x\n", pFileHeader->Machine);
	printf("pFileHeader->Characteristics=%x\n", pFileHeader->Characteristics);
	printf("pFileHeader->NumberOfSections=%x\n", pFileHeader->NumberOfSections);
	printf("pFileHeader->SizeOfOptionalHeader=%x\n", pFileHeader->SizeOfOptionalHeader);
}

void CPEUtil::PrintPEOptionalHeader()
{
	if (!CPEUtil::pOptionalHeader)
	{
		printf("PE��չͷ�����޷���\n");
		return;
	}
	printf("====================PE��չͷ====================\n");
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
	printf("====================PE��ͷ====================\n");
	printf("Secion number:%d\n", CPEUtil::pFileHeader->NumberOfSections);

	for (int i = 0; i < CPEUtil::pFileHeader->NumberOfSections; i++)
	{
		char name[9]{ 0 };
		memcpy(name, (CPEUtil::pSectionFirstHeader + i)->Name, 8);
		printf("Section name:%s\n", name);
	}
	
}