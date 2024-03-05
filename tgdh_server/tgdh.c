#include "tgdh.h"

// 兼容windows和linux的线程函数 processDaemon
#ifdef _WIN32
DWORD WINAPI processDaemon()
#else
void *processDaemon()
#endif
{
    // 初始化winsock
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf_log(log_file,"WSAStartup failed.\n");
        return 2;
    }
#endif

#ifdef _WIN32
    hMutex = CreateMutex(NULL, FALSE, NULL);
#else
    pthread_mutex_init(&mutex, NULL);
#endif

    // Create UDP socket
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address_str, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 创建接收队列
    queue = initQueue();

    // 创建数据包处理线程：出队、判断数据包类型、不同的数据包类型执行不同的操作
#ifdef _WIN32
    HANDLE hThread_packets = CreateThread(NULL, 0, processPackets, NULL, 0, NULL);
#else
    pthread_t tid_packets;
    pthread_create(&tid_packets, NULL, processPackets, NULL);
#endif

    // Main loop to receive packets
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    socklen_t len = sizeof(cliaddr);
    while (1)
    {
        int n = recvfrom(sockfd, (char *)packet, MAX_MSG_LEN, MSG_WAITALL,
                         (struct sockaddr *)&cliaddr, &len);
        if (n > 0)
        {
            packet->data[n - sizeof(DataHeader)] = '\0';
            enqueue(packet);
            fprintf_log(log_file, "udp: receive type: %u, rx_pkt_num:%d.\n", packet->header.type, rx_pkt_num);
            rx_pkt_num++;
            memset(packet, 0, sizeof(Packet));
        }
    }
#ifdef _WIN32
    CloseHandle(hThread_packets);
    CloseHandle(hMutex);
#else
    pthread_join(tid_packets, NULL);
#endif

#ifdef _WIN32
    WSACleanup();
#endif
}

// 初始化
void initTGDH()
{
    // 创建上下文变量
    kt_ctx = (keytree_context *)malloc(sizeof(keytree_context));
    memset(kt_ctx, 0, sizeof(keytree_context));
    strcpy(kt_ctx->group_name, TGDH_GROUP_NAME);
    kt_ctx->alpha = BN_new();
    kt_ctx->p = BN_new();

    for (int i = 0; i < NODE_NUM; i++)
    {
        kt_ctx->nodes[i].id = i;
    }
    //new ,no need selfkey
}

// 创建group，初始化密钥树，自己作为根节点，向服务器节点发送创建信息
// dataheader(type 0) + groupname + rounds + alpha + p + root_node
int createGroup()
{
    // 初始化树信息
    // 随机生成群组参数
    // BN_rand(kt_ctx->alpha, BLIND_KEY_LEN * 8, 0, 0);
    BN_set_word(kt_ctx->alpha, 2); // 选择一个常见的底数，也可以是其他值
    BN_generate_prime_ex(kt_ctx->p, KEY_LEN * 8, 0, NULL, NULL, NULL);
    kt_ctx->rounds = 0;
    kt_ctx->nodes[0].flag = 2;
    kt_ctx->nodes[0].addr = key_self->addr;
    kt_ctx->nodes[0].blind_key = generateBlindKey(key_self->self_key, kt_ctx->alpha, kt_ctx->p);
    kt_ctx->rounds = 1;
    Packet *packet = createCreatePacket0(); // 构造创建数据包
    // 发送数据包
    send2server(packet);
    // 释放资源
    free(packet);
    // 开启线程监听其他节点的回复
#ifdef _WIN32
    HANDLE hThread_daemon = CreateThread(NULL, 0, processDaemon, NULL, 0, NULL);
#else
    pthread_t tid_daemon;
    pthread_create(&tid_daemon, NULL, processDaemon, NULL);
#endif
}

// 查询密钥树，向服务器节点发送查询请求，并将回复的密钥树信息存储在本地
void queryGroup()
{
    // tcp通信 查询密钥树
    Packet *packet = createQueryPacket(); // 构造查询数据包
    char *buffer;
    int *len;
    query2server(packet, &buffer, len);
    // 解析回复的密钥树信息
    parseKeyTree(buffer);

    free(packet);
}

// 节点加入
int joinGroup()
{
    // 向服务器查询密钥树
    queryGroup();

    key_self->id = -1; //表示群组外成员
    // 向sponsor节点发送加入请求及自己的blinded key
    Packet *packet = createJoinPacket1();
    fprintf_log(log_file,"findJoinSponsorID: %d\n",findJoinSponsorID());
    send2node(packet, findJoinSponsorID());

    // TODO:修改自己的id、
    key_self->id = findRightChildID(findJoinSponsorID());
    free(packet);
    // 开启线程监听其他节点的回复
#ifdef _WIN32
    HANDLE hThread_daemon = CreateThread(NULL, 0, processDaemon, NULL, 0, NULL);
#else
    pthread_t tid_daemon;
    pthread_create(&tid_daemon, NULL, processDaemon, NULL);
#endif
}

// 节点离开
int leaveGroup()
{
    // 向sponsor节点发送离开请求
    Packet *packet = createLeavePacket2();
    send2node(packet, findLeaveSponsorID(key_self->id));
    // 释放资源
    free(packet);
    free(key_self);
    free(kt_ctx);
}

// 更新密钥树，自己作为sponsor节点广播自己路径上的blinded key
int updateGroup()
{
    // 向所有叶子节点和服务器发送广播报文
    Packet *packet = createUpdatePacket5();
    broadcast2leaf(packet);
    // 释放资源
    free(packet);
}
