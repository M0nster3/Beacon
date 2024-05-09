#pragma once
#include "Util.h"


typedef HMODULE(__stdcall* fpLoadLibraryA)(LPCSTR lpLibFileName);
typedef BOOL(__stdcall* fpFreeLibrary)(HMODULE hLibModule);
typedef FARPROC(__stdcall* fpGetProcAddress)(HMODULE hModule, LPCSTR  lpProcName);
typedef HMODULE(__stdcall* fpGetModuleHandleA)(LPCSTR lpModuleName);
typedef void(__cdecl* fpBeaconDataParse)(formatp* parser, char* buffer, int size);
typedef char* (__cdecl* fpBeaconDataPtr)(formatp* parser, int size);
typedef int(__cdecl* fpBeaconDataInt)(formatp* parser);
typedef short(__cdecl* fpBeaconDataShort)(formatp* parser);
typedef int(__cdecl* fpBeaconDataLength)(formatp* parser);
typedef char* (__cdecl* fpBeaconDataExtract)(formatp* parser, int* size);
typedef void(__cdecl* fpBeaconFormatAlloc)(formatp* format, int maxsz);
typedef void(__cdecl* fpBeaconFormatReset)(formatp* format);
typedef void(__cdecl* fpBeaconFormatAppend)(formatp* format, char* text, int len);
typedef void(__cdecl* fpBeaconFormatPrintf)(formatp* format, char* fmt, ...);
typedef char* (__cdecl* fpBeaconFormatToString)(formatp* format, int* size);
typedef void(__cdecl* fpBeaconFormatFree)(formatp* format);
typedef void(__cdecl* fpBeaconFormatInt)(formatp* format, int value);
typedef void(__cdecl* fpBeaconOutput)(int type, char* data, int len);
typedef void(__cdecl* fpBeaconPrintf)(int type, char* fmt, ...);
typedef void(__cdecl* fpBeaconErrorD)(int BeaconErrorsType, DWORD error_code);
typedef void(__cdecl* fpBeaconErrorDD)(int BeaconErrorsType, int err_msg, u_long err_code_msg);
typedef void(__cdecl* fpBeaconErrorNA)(int BeaconErrorsType);
typedef BOOL(__cdecl* fpBeaconUseToken)(HANDLE token);
typedef BOOL(__cdecl* fpBeaconIsAdmin)();
typedef void(__cdecl* fpBeaconRevertToken)();
typedef void(__cdecl* fpBeaconGetSpawnTo)(BOOL x86, char* buffer, int length);
typedef void(__cdecl* fpBeaconInjectProcess)(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
typedef void(__cdecl* fpBeaconInjectTemporaryProcess)(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
typedef BOOL(__cdecl* fpBeaconSpawnTemporaryProcess)(BOOL x86, BOOL ignoreToken, STARTUPINFOA* si, PROCESS_INFORMATION* pInfo);
typedef void(__cdecl* fpBeaconCleanupProcess)(PROCESS_INFORMATION* pInfo);
typedef BOOL(__cdecl* fptoWideChar)(char* src, wchar_t* dst, unsigned int max);

typedef struct {
	fpLoadLibraryA LoadLibraryA;
	fpFreeLibrary FreeLibrary;
	fpGetProcAddress GetProcAddress;
	fpGetModuleHandleA GetModuleHandleA;
	fpBeaconDataParse BeaconDataParse;
	fpBeaconDataPtr BeaconDataPtr;
	fpBeaconDataInt BeaconDataInt;
	fpBeaconDataShort BeaconDataShort;
	fpBeaconDataLength BeaconDataLength;
	fpBeaconDataExtract BeaconDataExtract;
	fpBeaconFormatAlloc BeaconFormatAlloc;
	fpBeaconFormatReset BeaconFormatReset;
	fpBeaconFormatAppend BeaconFormatAppend;
	fpBeaconFormatPrintf BeaconFormatPrintf;
	fpBeaconFormatToString BeaconFormatToString;
	fpBeaconFormatFree BeaconFormatFree;
	fpBeaconFormatInt BeaconFormatInt;
	fpBeaconOutput BeaconOutput;
	fpBeaconPrintf BeaconPrintf;
	fpBeaconErrorD BeaconErrorD;
	fpBeaconErrorDD BeaconErrorDD;
	fpBeaconErrorNA BeaconErrorNA;
	fpBeaconUseToken BeaconUseToken;
	fpBeaconRevertToken BeaconRevertToken;
	fpBeaconIsAdmin BeaconIsAdmin;
	fpBeaconGetSpawnTo BeaconGetSpawnTo;
	fpBeaconInjectProcess BeaconInjectProcess;
	fpBeaconInjectTemporaryProcess BeaconInjectTemporaryProcess;
	fpBeaconSpawnTemporaryProcess BeaconSpawnTemporaryProcess;
	fpBeaconCleanupProcess BeaconCleanupProcess;
	fptoWideChar toWideChar;
	char* end;
	
}BeaconInternalFunctions;

typedef struct 
{
	short Type;
	short id;
	int offset;
	int OffsetInSection;
}BeaconBofRelocation;