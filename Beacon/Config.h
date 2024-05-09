#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
unsigned char* metadata_prepend;
unsigned char* metadata_header;
extern const char Http_get_uri[];
extern const char Http_Post_uri[];
unsigned char* Http_post_id_prepend;
unsigned char* Http_post_id_append;
unsigned char* Http_post_client_output_prepend;
unsigned char* Http_post_client_output_append;
extern unsigned char* pub_key_str;
unsigned char* Response_prepend;
unsigned char* Response_append;
unsigned char IV[];
int SleepTime;
unsigned char AESRandaeskey[16];
unsigned char Hmackey[16];
int Counter;
int clientID;