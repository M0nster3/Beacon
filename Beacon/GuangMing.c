/*
Author: Bobby Cooke @0xBoku | https://github.com/boku7 | https://0xBoku.com | https://www.linkedin.com/in/bobby-cooke/
Credits / References: Pavel Yosifovich (@zodiacon),Reenz0h from @SEKTOR7net, @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique)
*/
#include <Windows.h>
#include "GuangMing.h"
#include <stdio.h>


PVOID ntdll = NULL;
PVOID ntdllExportTable = NULL;

PVOID ntdllExAddrTbl = NULL;
PVOID ntdllExNamePtrTbl = NULL;
PVOID ntdllExOrdinalTbl = NULL;

const char SyscallString[] = "NtAllocateVirtualMemory";
DWORD SyscallLen = 0;
PVOID SyscallAddr = NULL;
DWORD SyscallNumber = 0;



SYSTEM_PROCESS_INFORMATION* procinfo;

DWORD GetSyscallNumber(char* Page, int SyscallLen) {
	char SyscallString[32];
	memcpy(SyscallString, Page, SyscallLen);
	SyscallString[SyscallLen] = '\0';
	printf("###################################################################\r\n");
	// Use Position Independent Shellcode to resolve the address of NTDLL and its export tables
	ntdll = getntdll();
	printf("[+] %p : NTDLL Base Address\r\n", ntdll);

	ntdllExportTable = getExportTable(ntdll);
	printf("[+] %p : NTDLL Export Table Address\r\n", ntdllExportTable);

	ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdll);
	printf("[+] %p : NTDLL Export Address Table Address\r\n", ntdllExAddrTbl);

	ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdll);
	printf("[+] %p : NTDLL Export Name Pointer Table Address\r\n", ntdllExNamePtrTbl);

	ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdll);
	printf("[+] %p : NTDLL Export Ordinal Table Address\r\n", ntdllExOrdinalTbl);
	printf("###################################################################\r\n\r\n");
	// Find the address of NTDLL.NtQuerySystemInformation by looping through NTDLL export tables
	//SyscallLen = strl(SyscallString);
	printf("[-] Looping through NTDLL Export tables to discover the address for NTDLL.%s..\r\n", SyscallString);
	SyscallAddr = getApiAddr(
		SyscallLen,
		SyscallString,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	printf("[+] %p : NTDLL.%s Address\r\n\r\n", SyscallAddr, SyscallString);
	printf("[-] Using HellsGate technique to discover syscall for %s..\r\n", SyscallString);
	
	SyscallNumber = findSyscallNumber(SyscallAddr);
	// HalosGate technique to recover the systemcall number. Used when stub in NTDLL is hooked. This evades/bypasses EDR Userland hooks
	if (SyscallNumber == 0) {
		printf("[!] Failed to discover the syscall number for . The API is likely hooked by EDR\r\n");
		printf("[-] Using HalosGate technique to discover syscall for ..\r\n");
		DWORD index = 0;
		while (SyscallNumber == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			SyscallNumber = halosGateUp(SyscallAddr, index);
			if (SyscallNumber) {
				SyscallNumber = SyscallNumber - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			SyscallNumber = halosGateDown(SyscallAddr, index);
			if (SyscallNumber) {
				SyscallNumber = SyscallNumber + index;
				break;
			}
		}
	}
	

	// Allocate the buffer for the process information returned from NtQuerySystemInformation
	//ULONG size = 1 << 18;
	//PVOID base_addr = NULL;
	//SIZE_T buffSize1 = (SIZE_T)size;
	//ULONG required = 0;

	// NtAllocateVirtualMemory
	
	return SyscallNumber;
	//// NtQuerySystemInformation
	//HellsGate(ntQrySysInfoSyscallNumber);

	//NTSTATUS status = HellDescent(SystemProcessInformation, base_addr, size, &required);

	//if (status == STATUS_BUFFER_TOO_SMALL) {
	//	size = required + (1 << 14);
	//	SIZE_T buffSize2 = size;
	//	// NtAllocateVirtualMemory
	//	HellsGate(SyscallNumber);
	//	HellDescent((HANDLE)-1, &base_addr, 0, &buffSize2, MEM_COMMIT | MEM_RESERVE, SyscallString_READWRITE);
	//}

	//NTSTATUS status2 = HellDescent(SystemProcessInformation, base_addr, size, &required);

	//procinfo = (SYSTEM_PROCESS_INFORMATION*)base_addr;
	//while (TRUE) {
	//	BOOL check = compExplorer(procinfo->ImageName.Buffer);
	//	if (check == 1) {
	//		printf("%ws | PID: %6u | PPID: %6u\n",
	//			procinfo->ImageName.Buffer,
	//			HandleToULong(procinfo->UniqueProcessId),
	//			HandleToULong(procinfo->InheritedFromUniqueProcessId)
	//		);
	//		break;
	//	}
	//	procinfo = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)procinfo + procinfo->NextEntryOffset);
	//}
	//return;
}