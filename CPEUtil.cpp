#include "CPEUtil.h"

CPEUtil::CPEUtil()
{
	this->fileBuff = NULL;
	this->fileSize = NULL;
	this->pDosHeader = NULL;
	this->pNtHeaders = NULL;
	this->pFileHeader = NULL;
	this->pOptionalHeader = NULL;
	this->pSectionFirstHeader = NULL;
}

CPEUtil::~CPEUtil()
{
	if (fileBuff)
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
	fileSize = GetFileSize(hFile, NULL);

	// 读取文件缓冲区
	fileBuff = new char[fileSize];

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
	pDosHeader = (PIMAGE_DOS_HEADER) fileBuff;

	// 判断是否为有效的pe文件
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	// 获取NT头
	pNtHeaders = (PIMAGE_NT_HEADERS) (fileBuff + pDosHeader->e_lfanew);

	// 判断PE头是否有效
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	// 获取标准pe头
	pFileHeader = &pNtHeaders->FileHeader;

	// 获取可选pe头
	pOptionalHeader = &pNtHeaders->OptionalHeader;

	// 获取第一个区段头
	pSectionFirstHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	return TRUE;
}

void CPEUtil::PrintPEHeader()
{
	if (!pFileHeader) {
		printf("PE标准头错误，无法打开\n");
		return;
	}
	printf("\n====================PE标准头====================\n");
	printf("pFileHeader->Machine=%x\n", pFileHeader->Machine);
	printf("pFileHeader->Characteristics=%x\n", pFileHeader->Characteristics);
	printf("pFileHeader->NumberOfSections=%x\n", pFileHeader->NumberOfSections);
	printf("pFileHeader->SizeOfOptionalHeader=%x\n", pFileHeader->SizeOfOptionalHeader);
}

void CPEUtil::PrintPEOptionalHeader()
{
	if (!pOptionalHeader)
	{
		printf("PE扩展头错误，无法打开\n");
		return;
	}
	printf("\n====================PE扩展头====================\n");
	printf("pOptionalHeader->AddressOfEntryPoint=%x\n", pOptionalHeader->AddressOfEntryPoint);
	printf("pOptionalHeader->ImageBase=%x\n", pOptionalHeader->ImageBase);
	printf("pOptionalHeader->SectionAlignment=%x\n", pOptionalHeader->SectionAlignment);       // 内存对齐大小
	printf("pOptionalHeader->FileAlignment=%x\n", pOptionalHeader->FileAlignment);			   // 文件对齐大小
	printf("pOptionalHeader->SizeOfImage=%x\n", pOptionalHeader->SizeOfImage);				   // 文件在内存中的大小，按SectionAlignment
	printf("pOptionalHeader->SizeOfHeaders=%x\n", pOptionalHeader->SizeOfHeaders);             // DOS头+NT头+标准PE头+区段头，按照FileAlignment对齐后大小
	printf("pOptionalHeader->SizeOfCode=%x\n", pOptionalHeader->SizeOfCode);
	printf("pOptionalHeader->NumberOfRvaAndSizes=%x\n", pOptionalHeader->NumberOfRvaAndSizes);
}

/*
打印区段头
	typedef struct _IMAGE_SECTION_HEADER {
		BYTE Name[IMAGE_SIZEOF_SHORT_NAME] 8; // 区段名称，此处跟字符串不一样，不会以0结尾
		union {
			DWORD PhysicalAddress;
			DWORD VirtualSize;
		} Misc; // 该区段在内存中的真是大小（未对齐）
		DWORD VirtualAddress;         // 区段在内存中的偏移值， + ImageBase为真正的地址
		DWORD SizeOfRawData;          // 区段在文件中对齐后大小
		DWORD PointerToRawData;       // 区段在文件中的偏移位置
	}
*/
void CPEUtil::PrintSectionHeaders()
{
	printf("\n====================PE区段头====================\n");
	printf("Secion number:%d\n", pFileHeader->NumberOfSections);

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		char name[9]{ 0 };
		memcpy(name, (pSectionFirstHeader + i)->Name, 8);
		printf("Section name:%s\tMisc(内存中真实大小):%x\tVirtualAddress(内存中偏移值):%x\tSizeOfRawData(文件中对齐后的大小):%x\tPointerToRawData(文件中的偏移位置):%x\n", 
			name, (pSectionFirstHeader + i)->Misc, (pSectionFirstHeader + i)->VirtualAddress, 
			(pSectionFirstHeader + i)->SizeOfRawData, (pSectionFirstHeader + i)->PointerToRawData);
	}
	
}

/*
	RVA转FOA
	1. 判断RVA是否在PE头区。在pe头区RVA与FOA相等，直接返回RVA。
	1.1 对比第一个节表头VirtualAddress
	1.2 若RVA < VirtualAddress，则说明RVA在pe头区
	2. 若RVA没有在pe头区，就遍历节表头，寻找这个RVA位于哪个节表区。
	2.1 循环遍历节表头，在该节表头内满足下列条件
	2.2 VirtualAddress <= RVA <= VirtualAddress + SizeOfRawData
	2.3 即可确定RVA位于哪个节表
	3. 找到RVA对应的节表区头后，计算并返回FOA的值
	3.1 FOA = (RAV - VirtualAddress) + PointerToRawData;
*/
DWORD CPEUtil::RvaToFoa1(DWORD rva)
{
	/*
	FOA = 数据的RVA - 区段的RVA + 区段的FOA
	*/
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	// 判断rva是否在pe头区
	if (rva < pSectionHeader->VirtualAddress)
	{
		if (rva < pSectionHeader->PointerToRawData)
		{
			return rva;
		}
		return NULL;
	}

	// 循环遍历节表头
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		// 遍历节表头，第一次不遍历
		if (i)
		{
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD) pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
		}

		// 判断是否大于此节表的RVA
		if (rva >= pSectionHeader->VirtualAddress)
		{
			if (rva <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			{
				// 计算FOA
				return (rva - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData; 
			}
			else
			{
				return NULL;
			}
		}

		//if (rva >= pSectionFirstHeader->VirtualAddress && rva < (pSectionFirstHeader->VirtualAddress + pSectionFirstHeader->Misc.VirtualSize))
		//{
		//	// FOA = 数据的RVA - 区段的RVA + 区段的FOA
		//	return rva - pSectionFirstHeader->VirtualAddress + pSectionFirstHeader->PointerToRawData;
		//}
	}
	return NULL;
}

DWORD CPEUtil::RvaToFoa(DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	// 循环遍历区段
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		// rva >= 区段的首地址 && rva < 区段的首地址 + 区段的大小， 说明在此区段内
		if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
		{

			// FOA = 数据RVA - 区段RVA + 区段FOA
			return rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}

		// 下一个区段
		pSectionHeader++;
	}
	return rva;
}

/*
  解析导出表
*/
void CPEUtil::GetExportTable()
{
	if (!pOptionalHeader)
	{
		printf("PE扩展头错误，无法打开\n");
		return;
	}

	// 数据目录
	IMAGE_DATA_DIRECTORY directory = pOptionalHeader->DataDirectory[0];

	// 获取导出表foa
	DWORD foa = RvaToFoa(directory.VirtualAddress);

	// 获取导出表的首地址
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(foa + fileBuff);

	char *dllName = RvaToFoa(pExport->Name) + fileBuff; // KeyboadHookDll.dll
	printf("文件名称：%s\n", dllName);

	// 打印函数名称
	// 函数地址->函数序号->函数名
	DWORD* funAddr = (DWORD*)(RvaToFoa(pExport->AddressOfFunctions) + fileBuff);

	// 函数序号
	WORD* peot = (WORD*)(RvaToFoa(pExport->AddressOfNameOrdinals) + fileBuff);

	// 函数名
	DWORD* pent = (DWORD*)(RvaToFoa(pExport->AddressOfNames) + fileBuff);


	for (int i = 0; i < pExport->NumberOfFunctions; i++)
	{
			printf("函数地址为：%p\n", *funAddr);

			for (int j = 0; j < pExport->NumberOfNames; j++)
			{
				if (peot[j] == i)
				{
					char* funName = (RvaToFoa(pent[j]) + fileBuff);
					printf("函数名称为：%s\n", funName);
					break;
				}
			}
			funAddr++;
	}
}

/*
解析导入表
*/
void CPEUtil::GetImportTables()
{
	IMAGE_DATA_DIRECTORY directory = pOptionalHeader->DataDirectory[1];

	// 获取导入表地址
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFoa(directory.VirtualAddress) + fileBuff);

	printf("\n====================PE导入表====================\n");

	while (pImport->OriginalFirstThunk)
	{
		char* dllName = RvaToFoa(pImport->Name) + fileBuff;
		printf("DLL文件名称为：%s\n", dllName);
		printf("TimeDateStamp=%d\n", pImport->TimeDateStamp);

		PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)(RvaToFoa(pImport->OriginalFirstThunk) + fileBuff);

		while (pThunkData->u1.Function)
		{

			// 判断是按名称导入还是按序号导入 
			/*
			如何判断一个数的最高位是否为1呢？可以让这个数与另一个个最高位为1的数进行And运算，如果最高位为0结果就是0
			举例：
			10进制140（1000 1100）的最高位是否为0？140转化位2进制为1000 1100，最高位为1的2进制数为1000 0000，转化成10进制：128
			1000 1100
			1000 0000
			---------
			1000 0000  结果>0
			10进制112（0111 0000）的最高为是否为1？
			0111 0000
			1000 0000
			---------
			0000 0000  结果=0
			IMAGE_ORDINAL_FLAG32 为32位最高位为1的数
			IMAGE_ORDINAL_FLAG64 为64位最高位为1的数
			IMAGE_SNAP_BY_ORDINAL32() 可以判断最高位是否位1
			*/
			if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32 != 1)
			{
				// 按序号导入
				printf("按序号导入：%d\n", pThunkData->u1.Ordinal & 0x7FFFFFF);
			}
			else
			{
				// 按名称导入
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pThunkData->u1.AddressOfData) + fileBuff);
				printf("按名称导入:%s\n", pImportName->Name);
			}
			pThunkData++;
		}
		pImport++;
	}

}

/*
解析重定位表
*/
void CPEUtil::GetReLocation()
{

	IMAGE_DATA_DIRECTORY directory = pOptionalHeader->DataDirectory[5];

	// 获取重定位表地址
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFoa(directory.VirtualAddress) + fileBuff);

	while (1)
	{
		if (pRelocation->VirtualAddress == 0)
		{
			break;
		}

		// 计算出有多少块
		DWORD blockNumber = ((DWORD)pRelocation->SizeOfBlock - 8) / 2;

		// 定义一个指针，指向第一个小格子
		WORD* pRelocOffset = (WORD*)pRelocation + 4;

		for (int i = 0; i < blockNumber; i++)
		{
			// 高4位是否为3
			if (*pRelocOffset & 0x3000 == 0x3000)
			{

				// 如果是3，则取低12位
				WORD low12 = *pRelocOffset & 0x0FFF;

				DWORD rva = low12 + pRelocation->VirtualAddress;

				printf("RVA=%.8x\n", rva);
			}
			pRelocOffset++;
		}
		pRelocation = pRelocation + pRelocation->SizeOfBlock;
	}

	
}
