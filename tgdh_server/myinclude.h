#ifndef _MYINCLUDE_H
#define _MYINCLUDE_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifdef _WIN32
WSADATA wsaData;
#endif



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <openssl/bn.h>
#include <stdarg.h>
#include <time.h>

#define TGDH_GROUP_NAME "tgdh_group"
#define TOKEN "test_token"





#endif