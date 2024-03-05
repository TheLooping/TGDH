#include "tgdh.h"
#define SERVER_IP TCP_SERVER_IP // 要修改为服务器IP
#define SERVER_PORT TCP_SERVER_PORT
#define BUFFER_SIZE MAX_MSG_LEN

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
PacketQueue *queue;
keytree_context *kt_ctx;
keytree_self *key_self;


int port;
char *ip_address_str;
int tx_pkt_num = 0;
int rx_pkt_num = 0;
FILE *log_file;


int kt_mutex = 0; //new
int udpListen(); //new
void handle_client(int client_socket); //new
void *tcpListenQuery(void *arg); //new

int main()
{   
    char log_filename[20] = {'\0'};
    snprintf(log_filename, sizeof(log_filename), "log_server.txt");
    log_file = fopen(log_filename, "a");

    initTGDH(); //new
    pthread_t tid2;
    pthread_create(&tid2, NULL, tcpListenQuery, NULL);
    // 监听udp，其中线程函数processPackets维护密钥树节点状态更新
    udpListen();

    pthread_join(tid2, NULL);
    return 0;
}

// 接收来自节点的数据包，并解析到kt_ctx中
int udpListen()
{
    pthread_mutex_init(&mutex, NULL);
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
    servaddr.sin_addr.s_addr = inet_addr(UDP_SERVER_IP);
    servaddr.sin_port = htons(UDP_SERVER_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 创建接收队列
    queue = initQueue();

    // 创建数据包处理线程：出队、判断数据包类型、不同的数据包类型执行不同的操作

    pthread_t tid_packets;
    pthread_create(&tid_packets, NULL, processPackets, NULL);  //new

    // Main loop to receive packets
    char *buffer = (char *)malloc(sizeof(Packet));
    Packet *packet;
    socklen_t len = sizeof(cliaddr);
    while (1)
    {
        int n = recvfrom(sockfd, buffer, MAX_MSG_LEN, MSG_WAITALL,
                         (struct sockaddr *)&cliaddr, &len);
        if (n > 0)
        {
            packet = (Packet *)buffer;
            packet->data[n - sizeof(DataHeader)] = '\0';
            enqueue(packet);
            memset(packet, 0, MAX_MSG_LEN);
        }
    }
    free(buffer);

    pthread_join(tid_packets, NULL);
}

void handle_client(int client_socket)
{
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // 接收数据
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0)
    {
        perror("recv failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    fprintf(log_file,"\n");
    fprintf_log(log_file,"recive a query\n");
    // 判断数据包类型及参数
    // 查询数据包 header + groupname(32bytes) + token(32bytes)
    Packet *packet = (Packet *)buffer;
    if (packet->header.type == 0)
    {
        if (memcmp(packet->data, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME)) == 0)
        {
            if (memcmp(packet->data + 32, TOKEN, sizeof(TOKEN)) == 0)
            {
                char *response = createKeyTreePacket(); 
                DataHeader *header = (DataHeader *)response;
                int len = header->length + sizeof(DataHeader);
                send(client_socket, response, len, 0);
                fprintf_log(log_file,"send back the kt_ctx\n");
                return;
            }
            fprintf_log(log_file,"Invalid query: TOKEN wrong\n");
            return;
        }
        fprintf_log(log_file,"Invalid query: TGDH_GROUP_NAME wrong\n");
        return;
    }
    fprintf_log(log_file,"Invalid query: packet->header.type != 0\n");

    return;
}

// tcp监听线程

void *tcpListenQuery(void *arg)
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len;
    int pid;

    // 创建套接字
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 绑定IP和端口
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(TCP_SERVER_IP);
    server_addr.sin_port = htons(TCP_SERVER_PORT);
    if (bind(server_socket, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // 监听
    if (listen(server_socket, 5) < 0)
    {
        perror("listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // 接收连接并处理
    while (1)
    {
        client_addr_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0)
        {
            perror("accept failed");
            close(server_socket);
            exit(EXIT_FAILURE);
        }

        // 等待kt_mutex
        while (kt_mutex == 1)
        {
            usleep(100000);
        }

        handle_client(client_socket);

        // // 创建子进程处理客户端请求
        // pid = fork();
        // if (pid < 0)
        // {
        //     perror("fork failed");
        //     close(client_socket);
        //     continue;
        // }
        // else if (pid == 0)
        // {                                // 子进程
        //     close(server_socket); // 关闭在子进程中不需要的套接字
        //     handle_client(client_socket);
        //     close(client_socket);
        //     exit(EXIT_SUCCESS);
        // }
        // else
        // {                                // 父进程
        //     close(client_socket); // 父进程不需要处理客户端请求，关闭客户端套接字
        // }
    }
    close(server_socket);
    return 0;
}
