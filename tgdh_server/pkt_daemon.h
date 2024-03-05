#ifndef PKT_DAEMON_H
#define PKT_DAEMON_H
#include "keytree.h"

// #define PORT 8888 // 本地UDP监听端口，IP为本地任一IP，与密钥树和keytree_self相同
#define MAX_MSG_LEN 1024
#define MAX_MSG_SIZE 10
#define BUFSIZE 10240

// 定义tcp服务器地址及端口 192.168.140.130 6666
#define TCP_SERVER_IP "192.168.140.130"
#define TCP_SERVER_PORT 6666
#define UDP_SERVER_IP TCP_SERVER_IP
#define UDP_SERVER_PORT 8888




// 数据包头结构体
typedef struct {
    uint8_t type;// 0查询 1加入 2离开 3广播BK 4更新
    int length;// data的长度，后续长度
} DataHeader;

typedef struct {
    DataHeader header;
    char data[MAX_MSG_LEN];
} Packet;

typedef struct {
    int front; // 队列头指针
    int rear;  // 队列尾指针
    int size;  // 当前队列中元素的数量
    Packet packets[MAX_MSG_SIZE];    
} PacketQueue;


extern PacketQueue *queue;
extern int tx_pkt_num;
extern int rx_pkt_num;
extern char *ip_address_str;
extern int port;
extern FILE *log_file;
extern int kt_mutex; //new


#ifndef MY_MUTEX
#define MY_MUTEX
extern pthread_mutex_t mutex;
#endif


PacketQueue* initQueue();
void enqueue(Packet *packet);
Packet *dequeue();

Packet *createQueryPacket(); // TCP 0 查询 to server

Packet *createCreatePacket0(); // 0 创建时通告 to server
Packet *createJoinPacket1(); // 1 加入 to sponsor
Packet *createLeavePacket2(); // 2 离开 to sponsor
Packet *createUpdatePacket3(); // 3 加入广播BK to leaf
Packet *createUpdatePacket4(int nodeID); // 4 离开广播BK to leaf
Packet *createUpdatePacket5(); // 5 更新广播BK to leaf
char *createKeyTreePacket();
void parseKeyTree(char *buffer); // TCP 解析服务器的响应结果
void parsePacket0(char *buffer); // 创建 server解析
void parsePacket1(char *buffer); // 加入 sponsor
int parsePacket2(char *buffer); // 离开 sponsor
void parsePacket3(char *buffer); // 加入广播BK  leaf
void parsePacket4(char *buffer); // 离开广播BK  leaf
void parsePacket5(char *buffer); // 更新广播BK  leaf



void handlePacket(Packet *packet);


// 处理数据包：出队、判断数据包类型、不同的数据包类型执行不同的操作
#ifdef _WIN32
DWORD WINAPI processPackets();
#else
void *processPackets();
#endif

// 向服务器节点发送tcp请求，将回复的信息存储在buffer
void query2server(Packet *packet, char **buffer, int *len);

// 向对应ID的节点发送udp报文 （仅发送）
void send2node(Packet *packet, int nodeID);

// 向服务器节点发送udp报文 （仅发送）
void send2server(Packet *packet);

// 向所有叶子节点发送广播报文 （仅发送）
void broadcast2leaf(Packet *packet);

#endif /* UDP_PACKET_H */
