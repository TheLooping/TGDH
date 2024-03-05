#include "pkt_daemon.h"

PacketQueue *initQueue()
{
    PacketQueue *queue = (PacketQueue *)malloc(sizeof(PacketQueue));
    queue->front = 0;
    queue->rear = -1;
    queue->size = 0;
    return queue;
}

// 判断队列是否为空
int isEmpty()
{
    return queue->size == 0;
}
// 判断队列是否已满
int isFull()
{
    return queue->size == MAX_MSG_SIZE;
}

// 入队操作
void enqueue(Packet *packet)
{
#ifdef _WIN32
    WaitForSingleObject(hMutex, INFINITE);
#else
    pthread_mutex_lock(&mutex);
#endif
    if (!isFull(queue))
    {
        queue->rear = (queue->rear + 1) % MAX_MSG_SIZE;
        memcpy(&(queue->packets[queue->rear]), packet, sizeof(Packet));
        queue->size++;
    }
    else
    {
        fprintf_log(log_file,"Queue is full, cannot enqueue %d\n", queue->size);
    }
#ifdef _WIN32
    ReleaseMutex(hMutex);
#else
    pthread_mutex_unlock(&mutex);
#endif
}

// 出队操作
Packet *dequeue()
{
#ifdef _WIN32
    WaitForSingleObject(hMutex, INFINITE);
#else
    pthread_mutex_lock(&mutex);
#endif
    Packet *packet = NULL;
    if (!isEmpty())
    {
        packet = (Packet *)malloc(sizeof(Packet));
        memcpy(packet, &(queue->packets[queue->front]), sizeof(Packet));
        queue->front = (queue->front + 1) % MAX_MSG_SIZE;
        queue->size--;
    }

#ifdef _WIN32
    ReleaseMutex(hMutex);
#else
    pthread_mutex_unlock(&mutex);
    return packet;
#endif
}

// 构造查询数据包 header + groupname(32bytes) + token(32bytes)
Packet *createQueryPacket()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 0;
    int index = 0;
    // groupname 32bytes
    memcpy(packet->data + index, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // token 32bytes
    memcpy(packet->data + index, TOKEN, sizeof(TOKEN));
    index += 32;
    packet->header.length = index;

    return packet;
}

// 构造创建数据包 header + groupname(32bytes) + rounds(4bytes) + alpha(512bits) + p(512bits) + root_node(nodeID(4bytes) + flag(4bytes) + is_update(4bytes) + sockaddr_in(16bytes))
Packet *createCreatePacket0()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 0;
    // groupname 32bytes
    int index = 0;
    memcpy(packet->data, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // rounds 4bytes
    memcpy(packet->data + index, &(kt_ctx->rounds), sizeof(kt_ctx->rounds));
    index += 4;
    // alpha 512bits
    BN_bn2bin(kt_ctx->alpha, packet->data + index);
    index += KEY_LEN;
    // p 512bits
    BN_bn2bin(kt_ctx->p, packet->data + index);
    index += KEY_LEN;
    // root node
    memcpy(packet->data + index, &(kt_ctx->nodes[0].id), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[0].flag), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[0].is_update), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[0].addr), 16);
    index += 16;
    packet->header.length = index;

    return packet;
}

// 构造加入数据包 header + groupname(32bytes) + sockaddr_in(16bytes) + blinded key(512bytes)
Packet *createJoinPacket1()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 1;
    int index = 0;
    // groupname 32bytes
    memcpy(packet->data + index, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // sockaddr_in 16bytes
    memcpy(packet->data + index, &(key_self->addr), 16);
    index += 16;
    // blinded key 512bits
    // 计算blinded key
    BIGNUM *blinded_key = BN_new();
    blinded_key = generateBlindKey(key_self->self_key, kt_ctx->alpha, kt_ctx->p);
    BN_bn2bin(blinded_key, packet->data + index);
    index += BLIND_KEY_LEN;
    packet->header.length = index;
    BN_free(blinded_key);

    return packet;
}

// 构造离开数据包 header + groupname(32bytes) + nodeID(4bytes)
Packet *createLeavePacket2()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 2;
    int index = 0;
    // groupname 32bytes
    memcpy(packet->data + index, TGDH_GROUP_NAME, sizeof(TGDH_GROUP_NAME));
    index += 32;
    // nodeID 4bytes
    memcpy(packet->data + index, &(key_self->id), 4);
    index += 4;
    packet->header.length = index;

    return packet;
}

// 构造加入更新数据包 header + join_node * (nodeID(4bytes) + blinded key(512bits))
Packet *createUpdatePacket3()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 3;
    // 更新路径上的节点的blind_key 已更新(prasePacket1)

    // join节点；递归查找父节点 将更新的blinded key存储在packet中
    int index = 0;
    // 兄弟节点是join节点
    int id = findSiblingID(key_self->id);
    memcpy(packet->data + index, &(kt_ctx->nodes[id].id), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[id].flag), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[id].is_update), 4);
    index += 4;
    memcpy(packet->data + index, &(kt_ctx->nodes[id].addr), 16);
    index += 16;
    BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
    index += BLIND_KEY_LEN;

    id = key_self->id;
    while (id != 0)
    {
        memcpy(packet->data + index, &id, 4);
        index += 4;
        BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
        index += BLIND_KEY_LEN;
        id = findParentID(id);
        kt_ctx->nodes[id].is_update = 0; // 复位
    }
    packet->header.length = index;

    return packet;
}
// 构造离开数据包 header + leave_node_id + n * (nodeID(4bytes) + blinded key(512bits))
Packet *createUpdatePacket4(int nodeID)
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 4;
    // 离开节点；递归查找父节点 将更新的blinded key存储在packet中
    int index = 0;
    memcpy(packet->data + index, &nodeID, 4);
    index += 4;
    // 更新路径上的节点的blind_key 已更新(prasePacket2)
    int id = key_self->id;
    while (id != 0)
    {
        memcpy(packet->data + index, &id, 4);
        index += 4;
        BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
        index += BLIND_KEY_LEN;
        id = findParentID(id);
        kt_ctx->nodes[id].is_update = 0; // 复位
    }
    packet->header.length = index;

    return packet;
}
// 构造更新数据包 header + n * (nodeID(4bytes) + blinded key(512bits))
Packet *createUpdatePacket5()
{
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    memset(packet, 0, sizeof(Packet));
    packet->header.type = 5;

    // 更新路径上的节点的blind_key
    updateGroupKey();
    // 递归查找父节点 将更新的blinded key存储在packet中
    int index = 0;
    int id = key_self->id;
    while (id != 0)
    {
        memcpy(packet->data + index, &id, 4);
        index += 4;
        BN_bn2bin(kt_ctx->nodes[id].blind_key, packet->data + index);
        index += BLIND_KEY_LEN;
        id = findParentID(id);
    }
    packet->header.length = index;

    return packet;
}

char *createKeyTreePacket()
{
    char *buffer = malloc(BUFSIZE);
    memset(buffer, 0, BUFSIZE);
    DataHeader *header = (DataHeader *)buffer;
    int index = sizeof(DataHeader);
    memcpy(buffer + index, kt_ctx->group_name, sizeof(kt_ctx->group_name));
    index += 32;
    memcpy(buffer + index, &(kt_ctx->rounds), 4);
    index += 4;
    BN_bn2bin(kt_ctx->alpha, buffer + index);
    index += KEY_LEN;
    BN_bn2bin(kt_ctx->p, buffer + index);
    index += KEY_LEN;
    for (int i = 0; i < NODE_NUM; i++)
    {
        memcpy(buffer + index, &(kt_ctx->nodes[i].id), 4);
        index += 4;
        memcpy(buffer + index, &(kt_ctx->nodes[i].flag), 4);
        index += 4;
        memcpy(buffer + index, &(kt_ctx->nodes[i].is_update), 4);
        index += 4;
        memcpy(buffer + index, &(kt_ctx->nodes[i].addr), 16);
        index += 16;
        if (i != 0){
            BN_bn2bin(kt_ctx->nodes[i].blind_key, buffer + index);
        }
        else{
            memset(buffer + index,0,KEY_LEN);
        }        
        index += KEY_LEN;
    }
    header->length = index - sizeof(DataHeader);
};

// 解析密钥树信息 server to join_node
void parseKeyTree(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    int index = sizeof(DataHeader);
    // 解析密钥树信息
    memcpy(kt_ctx->group_name, buffer + index, 32);
    index += 32;
    memcpy(&(kt_ctx->rounds), buffer + index, 4);
    index += 4;
    // kt_ctx->alpha = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    BN_set_word(kt_ctx->alpha, 2); // 选择一个常见的底数，也可以是其他值
    fprintf_log(log_file, "TODO: 需要重新改回来 \n");

    index += KEY_LEN;
    kt_ctx->p = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    for (int i = 0; i < NODE_NUM; i++)
    {
        memcpy(&(kt_ctx->nodes[i].id), buffer + index, 4);
        index += 4;
        memcpy(&(kt_ctx->nodes[i].flag), buffer + index, 4);
        index += 4;
        memcpy(&(kt_ctx->nodes[i].is_update), buffer + index, 4);
        index += 4;
        memcpy(&(kt_ctx->nodes[i].addr), buffer + index, 16);
        index += 16;
        if (i == 0){
            kt_ctx->nodes[i].blind_key = BN_new();
        }
        else{
            kt_ctx->nodes[i].blind_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        }        
        index += KEY_LEN;
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file, "Error: parseKeyTree failed.\n");

    // 释放资源
    free(header);
}

// 解析创建请求数据包(type 0) create to server
void parsePacket0(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 0)
    {
        fprintf_log(log_file,"Error: parseCreatePacket failed.\n");
        return;
    }
    int index = sizeof(DataHeader);
    // groupname 32bytes
    memcpy(kt_ctx->group_name, buffer + index, 32);
    index += 32;
    if (strcmp(kt_ctx->group_name, TGDH_GROUP_NAME) != 0)
    {
        fprintf_log(log_file,"Error: parseCreatePacket failed.\n");
        return;
    }
    // rounds 4bytes
    memcpy(&(kt_ctx->rounds), buffer + index, 4);
    index += 4;
    // alpha 512bits
    kt_ctx->alpha = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    // p 512bits
    kt_ctx->p = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    // root node
    memcpy(&(kt_ctx->nodes[0].id), buffer + index, 4);
    index += 4;
    memcpy(&(kt_ctx->nodes[0].flag), buffer + index, 4);
    index += 4;
    memcpy(&(kt_ctx->nodes[0].is_update), buffer + index, 4);
    index += 4;
    memcpy(&(kt_ctx->nodes[0].addr), buffer + index, 16);
    index += 16;
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file,"Error: parseCreatePacket failed.\n");
}

// 解析加入请求数据包(type 1) join_node to sponsor
void parsePacket1(char *buffer)
{

    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 1)
    {
        fprintf_log(log_file,"Error: parseJoinPacket failed.\n");
        return;
    }
    int index = sizeof(DataHeader);

    // groupname 32bytes
    char groupname[32];
    memcpy(groupname, buffer + index, 32);
    index += 32;

    if (strcmp(groupname, TGDH_GROUP_NAME) != 0)
    {
        fprintf_log(log_file,"Error: parseJoinPacket failed.\n");
        return;
    }
    // sockaddr_in 、blinded key
    keytree_node *node = (keytree_node *)malloc(sizeof(keytree_node));
    memcpy(&(node->addr), buffer + index, 16);
    index += 16;
    node->blind_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    // 加入kt_ctx, 更新路径上的节点的blind_key
    joinTree(node, key_self->self_key);

    // 验证长度
    if (index != header->length + sizeof(DataHeader))
    {
        fprintf_log(log_file,"Error: parseJoinPacket failed.\n");
    }
}

// 解析离开请求数据包(type 2) leave_node to sponsor
int parsePacket2(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 2)
    {
        fprintf_log(log_file,"Error: parseLeavePacket failed.\n");
        return -1;
    }
    int index = sizeof(DataHeader);
    // groupname 32bytes
    char groupname[32];
    memcpy(groupname, buffer + index, sizeof(TGDH_GROUP_NAME));
    index += 32;
    if (strcmp(groupname, TGDH_GROUP_NAME) != 0)
    {
        fprintf_log(log_file,"Error: parseLeavePacket failed.\n");
        return -1;
    }
    // nodeID 4bytes
    int nodeID = 0;
    memcpy(&nodeID, buffer + index, 4);
    index += 4;
    // 计算离开sponsor
    int leaveSponsorID = findLeaveSponsorID(nodeID);
    if (leaveSponsorID != key_self->id)
    {
        fprintf_log(log_file,"Error: parseLeavePacket failed.\n");
        return -1;
    }
    // 离开sponsor
    leaveTree(nodeID, key_self->self_key);
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file,"Error: parseLeavePacket failed.\n");
    // 释放资源
    return nodeID;
}

// 解析加入的BK更新信息(type 3) sponsor to all
// dataheader + keytree_node join_node + n * (nodeID + blinded_key)
void parsePacket3(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 3)
    {
        fprintf_log(log_file,"Error: parseUpdateBK failed.\n");
        return;
    }
    int index = sizeof(DataHeader);
    // keytree_node
    keytree_node *join_node = (keytree_node *)malloc(sizeof(keytree_node));
    memcpy(&(join_node->id), buffer + index, 4);
    index += 4;
    memcpy(&(join_node->flag), buffer + index, 4);
    index += 4;
    memcpy(&(join_node->is_update), buffer + index, 4);
    index += 4;
    memcpy(&(join_node->addr), buffer + index, 16);
    index += 16;
    join_node->blind_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
    index += KEY_LEN;
    
    // 加入kt_ctx
    nodeJoinTree(join_node);

    int id = 0;
    BIGNUM *blinded_key = BN_new();
    // 解析更新的BK信息
    int total_len = header->length + sizeof(DataHeader);
    while (index < total_len)
    {
        memcpy(&id, buffer + index, 4);
        index += 4;
        blinded_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
    }


    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file,"Error: parseUpdateBK failed.\n");

    // 释放资源
    BN_free(blinded_key);
}

// 解析离开的BK更新信息(type 4) sponsor to all
// dataheader + leave_node_id + n * (nodeID + blinded_key)
void parsePacket4(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 4)
    {
        fprintf_log(log_file,"Error: parseLeaveBK failed.\n");
        return;
    }
    int index = sizeof(DataHeader);
    int leave_node_id = 0;
    memcpy(&leave_node_id, buffer + index, 4);
    index += 4;
    nodeLeaveTree(leave_node_id);

    int id = 0;
    BIGNUM *blinded_key = BN_new();
    // 解析更新的BK信息
    while (index < header->length + sizeof(DataHeader))
    {
        memcpy(&id, buffer + index, 4);
        index += 4;
        blinded_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
        fprintf_log(log_file,"update node %d\n",id);
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file,"Error: parseLeaveBK failed.\n");

    // 释放资源
    BN_free(blinded_key);
}

// 解析更新的BK信息(type 5) sponsor to all
// dataheader + n * (nodeID + blinded_key)
void parsePacket5(char *buffer)
{
    DataHeader *header = (DataHeader *)buffer;
    if (header->type != 5)
    {
        fprintf_log(log_file,"Error: parseUpdateBK failed.\n");
        return;
    }
    int index = sizeof(DataHeader);
    int id = 0;
    BIGNUM *blinded_key = BN_new();
    // 解析更新的BK信息
    while (index < header->length + sizeof(DataHeader))
    {
        memcpy(&id, buffer + index, 4);
        index += 4;
        blinded_key = BN_bin2bn(buffer + index, KEY_LEN, NULL);
        updateNodeKey(id, blinded_key);
        index += KEY_LEN;
    }
    // 验证长度
    if (index != header->length + sizeof(DataHeader))
        fprintf_log(log_file,"Error: parseUpdateBK failed.\n");

    // 释放资源
    BN_free(blinded_key);
}

void handlePacket(Packet *packet)
{             
    // fprintf(log_file,"\n");

    // 处理数据包，判断数据包类型，不同的数据包类型执行不同的操作
    if (packet->header.type == 0)
    {
        fprintf_log(log_file,"parsePacket0.\n");
        fprintf_log(log_file,"receive udp(rx_pkt_num:%d ;type:0): receive a create infomatioin\n",rx_pkt_num);
        // 创建 (只有server节点才会收到创建包)
        parsePacket0((char *)packet);
        
    }
    else if (packet->header.type == 1)
    {
        fprintf_log(log_file,"parsePacket1.\n");
        fprintf_log(log_file,"receive udp(rx_pkt_num:%d ;type:1): as the sponsor, receive a join quest\n",rx_pkt_num);
        // 加入 (只有sponsor节点才会收到加入包)
        parsePacket1((char *)packet);
        // 发送加入广播包
        Packet *packet = createUpdatePacket3();
        usleep(20000); 
        broadcast2leaf(packet);
    }
    else if (packet->header.type == 2)
    {
        fprintf_log(log_file,"parsePacket2.\n");
        fprintf_log(log_file, "receive udp(rx_pkt_num:%d ;type:2): as the sponsor, receive a leave quest;\n",rx_pkt_num);        
        int leave_node_id = parsePacket2((char *)packet);
        fprintf_log(log_file, "rleave_node_id:%d\n", leave_node_id);        

        
        // 离开 (只有sponsor节点才会收到离开包)        
        // 发送离开广播包
        Packet *packet = createUpdatePacket4(leave_node_id);
        broadcast2leaf(packet);
    }
    else if (packet->header.type == 3)
    {
        fprintf_log(log_file,"parsePacket3.\n");
        fprintf_log(log_file,"receive udp (rx_pkt_num:%d ;type:3): sponsor to all member, a node join the group\n",rx_pkt_num);
        // 收到sponsor节点的加入广播包
        parsePacket3((char *)packet);        
        updateGroupKey();
    }
    else if (packet->header.type == 4)
    {
        fprintf_log(log_file,"parsePacket4.\n");        
        int *leave_node_id = (int *)((char *)packet + sizeof(DataHeader));
        fprintf_log(log_file,"receive udp (rx_pkt_num:%d ;type:4): sponsor to all member, node %d leave the group\n",rx_pkt_num,*leave_node_id);
        
        parsePacket4((char *)packet);
        updateGroupKey();
    }
    else if (packet->header.type == 5)
    {
        fprintf_log(log_file,"parsePacket5.\n");
        fprintf_log(log_file,"receive udp (rx_pkt_num:%d ;type:5): sponsor to all member, a node update its BK\n",rx_pkt_num);
        // 收到sponsor节点的更新广播包
        parsePacket5((char *)packet);        
        updateGroupKey();
    }
    else
    {
        fprintf_log(log_file,"Error: unknown packet type.\n");
    }
    printfTree();
    

}

// 处理数据包：出队、调用handlePacket函数
#ifdef _WIN32
DWORD WINAPI processPackets()
{
#else
void *processPackets()
{
#endif
    char info[64] = {'\0'};

    while (1)
    {
        Packet *packet = dequeue();
        // 处理数据包，判断数据包类型，不同的数据包类型执行不同的操作
        if (packet != NULL)
        {
            memset(info, 0, 64);
            handlePacket(packet);
            free(packet);            
        }
        // usleep(1000);
    }
}

// 兼容windows和linux的tcp请求函数
void query2server(Packet *packet, char **buffer, int *len)
{
    // 创建socket
    int sockfd;
    struct sockaddr_in servaddr;
    *buffer = (char *)malloc(BUFSIZE);
    memset(*buffer, 0, BUFSIZE);

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf_log(log_file,"WSAStartup failed.\n");
        return 1;
    }
#endif

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf_log(log_file,"socket creation failed\n");
        return;
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(TCP_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(TCP_SERVER_IP);
    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        fprintf_log(log_file,"connection with the server failed\n");
        return;
    }
    // 发送数据包
    packet->header.type = 0;
    send(sockfd, (char *)packet, packet->header.length + sizeof(DataHeader), 0);
    
    fprintf_log(log_file, "tcp:query to server\n");
    // 接收数据包
    int lenth = recv(sockfd, *buffer, BUFSIZE, 0);
    
    fprintf_log(log_file, "tcp:response from server\n");
    // 关闭socket
    close(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
}

// 向对应ID的节点发送udp报文 （仅发送） 兼容windows和linux
void send2node(Packet *packet, int nodeID)
{
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf_log(log_file,"WSAStartup failed.\n");
        return 1;
    }
#endif
    // 创建socket
    int sockfd;
    struct sockaddr_in servaddr;
    memcpy(&servaddr, &(kt_ctx->nodes[nodeID].addr), sizeof(servaddr));
    // 创建socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        return;
    }
    // 绑定发送端口号
    struct sockaddr_in addr;
    addr = key_self->addr;
    addr.sin_port = htons(port-3000);
    if (bind(sockfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // 发送数据包
    sendto(sockfd, (char *)packet, packet->header.length + sizeof(DataHeader), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));    
    
    fprintf_log(log_file, "udp:%d send to %d, type: %u, port: %d , tx_pkt_num:%d\n", key_self->id, nodeID, packet->header.type, ntohs(kt_ctx->nodes[nodeID].addr.sin_port), tx_pkt_num);
    tx_pkt_num++;
    // 关闭socket
    close(sockfd);
}

// 向服务器节点发送udp报文 （仅发送）
void send2server(Packet *packet)
{
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        fprintf_log(log_file,"WSAStartup failed.\n");
        return 1;
    }
#endif
    // 创建socket
    int sockfd;
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(UDP_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(UDP_SERVER_IP);
    // 创建socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        return;
    }
    // 发送数据包
    sendto(sockfd, (char *)packet, packet->header.length + sizeof(DataHeader), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));    
    fprintf_log(log_file, "udp:%d send to server, type: %u, tx_pkt_num:%d\n", key_self->id, packet->header.type, tx_pkt_num);
    tx_pkt_num++;
    
    // 关闭socket
    close(sockfd);
#ifdef _WIN32
    WSACleanup();
#endif
}

// 向所有叶子节点发送广播报文 （仅发送）
void broadcast2leaf(Packet *packet)
{
    int i;
    for (i = 0; i < NODE_NUM; i++)
    {
        if (kt_ctx->nodes[i].flag == 2 && key_self->id != i)
        {
            send2node(packet, i);
        }
    }
    send2server(packet);
}

