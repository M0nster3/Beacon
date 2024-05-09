//仅支持cl编译的x64 obj
#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#pragma warning(disable:4996)
void vPrintf(char* fmt) {
	printf(fmt);
}

int main()
{
	HANDLE hFile = CreateFile(L"self_delete.x6.o", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile error.\n");
		return 0;
	}
	int file_size = 0;
	file_size = GetFileSize(hFile, NULL);
	char* buff;
	buff = (char*)malloc(file_size);
	DWORD dwRead;
	if (!ReadFile(hFile, buff, file_size, &dwRead, NULL))
	{
		printf("ReadFile error.\n");
		return 0;
	}

	//COFF文件头
	PIMAGE_FILE_HEADER PECOFF_FileHeader = (PIMAGE_FILE_HEADER)buff;
	printf("Machine: %x \n", PECOFF_FileHeader->Machine);
	printf("NumberOfSections %d \n", PECOFF_FileHeader->NumberOfSections);
	printf("TimeDateStamp %d \n", PECOFF_FileHeader->TimeDateStamp);
	printf("PointerToSymbolTable %d \n", PECOFF_FileHeader->PointerToSymbolTable);
	printf("NumberOfSymbols %d \n", PECOFF_FileHeader->NumberOfSymbols);
	printf("SizeOfOptionalHeader %d \n", PECOFF_FileHeader->SizeOfOptionalHeader);
	printf("Characteristics %x \n", PECOFF_FileHeader->Characteristics);

	//SizeOfOptionalHeader no

	//COFF节表处理
	PIMAGE_SECTION_HEADER* PECOFF_SectionHeader_arr = (PIMAGE_SECTION_HEADER*)malloc(PECOFF_FileHeader->NumberOfSections * sizeof(PIMAGE_SECTION_HEADER));
	memset(PECOFF_SectionHeader_arr, 0, PECOFF_FileHeader->NumberOfSections * sizeof(PIMAGE_SECTION_HEADER));

	PIMAGE_SECTION_HEADER PECOFF_SectionHeader = (PIMAGE_SECTION_HEADER)(buff + sizeof(IMAGE_FILE_HEADER));


	for (size_t i = 0; i <= PECOFF_FileHeader->NumberOfSections - 1; i++)
	{
		PECOFF_SectionHeader_arr[i] = PECOFF_SectionHeader;
		printf("段名称 %s \n", PECOFF_SectionHeader->Name);
		printf("段大小 %d \n", PECOFF_SectionHeader->SizeOfRawData);
		PECOFF_SectionHeader++;

	}

	//重定位表
	int Relocation_len = 0;
	for (int i = 0; i <= PECOFF_FileHeader->NumberOfSections - 1; i++)
	{
		Relocation_len += PECOFF_SectionHeader_arr[i]->NumberOfRelocations;
	}

	int x = 0;
	PIMAGE_RELOCATION* PECOFF_Relocation_arr = (PIMAGE_RELOCATION*)malloc(Relocation_len * sizeof(PIMAGE_RELOCATION));
	memset(PECOFF_Relocation_arr, 0, Relocation_len * sizeof(PIMAGE_RELOCATION));

	for (int i = 0; i <= PECOFF_FileHeader->NumberOfSections - 1; i++)
	{

		if (PECOFF_SectionHeader_arr[i]->NumberOfRelocations)
		{
			PIMAGE_RELOCATION PECOFF_Relocation = (PIMAGE_RELOCATION)(buff + PECOFF_SectionHeader_arr[i]->PointerToRelocations);
			for (int y = 0; y < PECOFF_SectionHeader_arr[i]->NumberOfRelocations; y++)
			{
				PECOFF_Relocation_arr[x] = PECOFF_Relocation;
				PECOFF_Relocation++;
				x++;
			}
		}
	}
	//打印输出


	//符号表
	PIMAGE_SYMBOL PECOFF_SYMBOL = (PIMAGE_SYMBOL)(buff + PECOFF_FileHeader->PointerToSymbolTable);
	PIMAGE_SYMBOL* PECOFF_SYMBOL_arr = (PIMAGE_SYMBOL*)malloc(PECOFF_FileHeader->NumberOfSymbols * sizeof(PIMAGE_SYMBOL));
	memset(PECOFF_SYMBOL_arr, 0, PECOFF_FileHeader->NumberOfSymbols * sizeof(PIMAGE_SYMBOL));


	for (int i = 0; i <= PECOFF_FileHeader->NumberOfSymbols - 1; i++)
	{
		PECOFF_SYMBOL_arr[i] = PECOFF_SYMBOL;
		PECOFF_SYMBOL++;
	}
	//无需处理NumberOfAuxSymbols


	//处理重定位和函数指针

	char* Fun_ptr = buff + PECOFF_SectionHeader_arr[0]->PointerToRawData;
	for (int i = 0; i <= PECOFF_FileHeader->NumberOfSections - 1; i++)
	{

		if (PECOFF_SectionHeader_arr[i]->NumberOfRelocations)
		{
			PIMAGE_RELOCATION PECOFF_Relocation = (PIMAGE_RELOCATION)(buff + PECOFF_SectionHeader_arr[i]->PointerToRelocations);
			for (int y = 0; y < PECOFF_SectionHeader_arr[i]->NumberOfRelocations; y++)
			{

				int sys_index = PECOFF_Relocation->SymbolTableIndex;
				if (PECOFF_SYMBOL_arr[sys_index]->StorageClass == 3)
				{
					char* patch_data = buff + (PECOFF_Relocation->VirtualAddress + PECOFF_SectionHeader_arr[i]->PointerToRawData);

					*(DWORD*)patch_data = ((DWORD64)(buff + ((PECOFF_SYMBOL_arr[sys_index]->Value) + (PECOFF_SectionHeader_arr[PECOFF_SYMBOL_arr[sys_index]->SectionNumber - 1]->PointerToRawData))) - (DWORD64)(patch_data + 4));
				}
				else
				{
					if (!(PECOFF_SYMBOL_arr[sys_index]->N.Name.Short))
					{
						char* pstr = (buff + PECOFF_FileHeader->PointerToSymbolTable) + (PECOFF_FileHeader->NumberOfSymbols * sizeof(IMAGE_SYMBOL));
						pstr += (DWORD)(PECOFF_SYMBOL_arr[sys_index]->N.Name.Long);
						if (!strcmp(pstr, "__imp_vPrintf"))
						{
							char* patch_data = buff + (PECOFF_Relocation->VirtualAddress + PECOFF_SectionHeader_arr[i]->PointerToRawData);
							*(DWORD64*)Fun_ptr = (DWORD64)vPrintf;
							*(DWORD*)patch_data = ((DWORD64)Fun_ptr - (DWORD64)(patch_data + 4));
							DWORD64* ptr = (DWORD64*)Fun_ptr;
							ptr++;
							Fun_ptr = (char*)ptr;
						}
						else
						{
							pstr += 6;
							char* dllname;
							char* funname;
							dllname = strtok(pstr, "$");
							funname = strtok(NULL, "$");
							DWORD64 fun_add = (DWORD64)GetProcAddress(LoadLibraryA(dllname), funname);
							char* patch_data = buff + (PECOFF_Relocation->VirtualAddress + PECOFF_SectionHeader_arr[i]->PointerToRawData);
							*(DWORD64*)Fun_ptr = (DWORD64)fun_add;
							*(DWORD*)patch_data = ((DWORD64)Fun_ptr - (DWORD64)(patch_data + 4));
							DWORD64* ptr = (DWORD64*)Fun_ptr;
							ptr++;
							Fun_ptr = (char*)ptr;
						}
					}
				}
				PECOFF_Relocation++;
			}
		}
	}

	//寻找go函数作为入口点
	DWORD oep;
	for (int i = 0; i < PECOFF_FileHeader->NumberOfSymbols - 1; i++)
	{
		if (!strncmp((char*)(PECOFF_SYMBOL_arr[i]->N.ShortName), "go", 2))
		{
			oep = PECOFF_SYMBOL_arr[i]->Value;
		}
	}

	char* jmp = 0;
	for (int i = 0; i < PECOFF_FileHeader->NumberOfSections - 1; i++)
	{
		if (!strncmp((char*)PECOFF_SectionHeader_arr[i]->Name, ".text", 5))
		{
			jmp = (buff + PECOFF_SectionHeader_arr[i]->PointerToRawData + oep);
		}
	}
	printf("0x%016I64x \n", jmp);
	DWORD Protect;
	if (VirtualProtect(buff, file_size, PAGE_EXECUTE_READWRITE, &Protect) != 0)
	{
		((void(*)(void))jmp)();
	};
	//printf("%x",GetLastError());

	return 0;
}

