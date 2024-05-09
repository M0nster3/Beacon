#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>

typedef struct {
    size_t respsize;
    unsigned char* resqresult;
    int code;
}perform_requestresult;

perform_requestresult perform_get_request(unsigned char* url, struct curl_slist* headers);
unsigned char* parseGetResponse(unsigned char* data, size_t dataSize, size_t* responsedatalen);
unsigned char* parsePacket(unsigned char* decryptedBuf, uint32_t* totalLen, uint32_t* commandType, size_t* commandBuflen , size_t* jia,int* jiaci);
perform_requestresult perform_post_request(unsigned char* url, struct curl_slist* headers, const char* postData);