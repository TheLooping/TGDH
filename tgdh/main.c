#include "tgdh.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
PacketQueue *queue;
keytree_context *kt_ctx;
keytree_self *key_self;


int port;
char *ip_address_str;
int tx_pkt_num = 0;
int rx_pkt_num = 0;
FILE *log_file;

#define LOG_FILE_FORMAT "log_%d.txt"

int main(int argc, char *argv[])
{    
    if (argc != 3) {
        fprintf(stderr, "Usage: %s  <PORT>\n", argv[0]);
        exit(1);
    }
    ip_address_str = argv[1];
    port = atoi(argv[2]);

    char log_filename[20] = {'\0'};
    snprintf(log_filename, sizeof(log_filename), LOG_FILE_FORMAT, port);
    log_file = fopen(log_filename, "a");

    
    initTGDH();
    int state = 0; // 当前状态 0未加入 1已加入
    // 循环接收命令 create query join leave update exit
    char cmd[32];
    while(1){
        printf("Please input command: ");
        scanf("%s", cmd);
        if(strcmp(cmd, "create") == 0){
            // 第一个节点创建
            if(state == 0){
                // 创建密钥群
                createGroup();
                state = 1;                    
            }
            else{
                fprintf_log(log_file,"You have already created a group.\n");
            }
        }
        else if(strcmp(cmd, "query") == 0){            
            queryGroup();            
        }
        else if(strcmp(cmd, "join") == 0){
            if(state == 0){
                joinGroup();
                state = 1;
            }
            else{
                fprintf_log(log_file,"You have already joined a group.\n");
            }                
        }
        else if(strcmp(cmd, "leave") == 0){
            if(state == 0){
                fprintf_log(log_file,"You have not joined a group yet.\n");
            }
            else{
                leaveGroup();
                state = 0;
            }
            
            goto end;
        }
        else if(strcmp(cmd, "update") == 0){
            if(state == 0){
                fprintf_log(log_file,"You have not joined a group yet.\n");
            }
            else{
                updateGroup();
            }
        }
        else if(strcmp(cmd, "exit") == 0){
            if(state != 0){
                leaveGroup();
                state = 0;
            }
            fprintf_log(log_file,"exit.\n");
            goto end;
        }     
        else{
            printf("Invalid command. Please input create, join, leave or update.\n");
        }
    }

end:
    fprintf_log(log_file, "udp:rx_pkt_num:%d.\n", rx_pkt_num);
    fprintf_log(log_file, "udp:tx_pkt_num:%d.\n", tx_pkt_num);    
    fclose(log_file);
    
    printf("udp:rx_pkt_num:%d.\n", rx_pkt_num);
    printf("udp:tx_pkt_num:%d.\n", tx_pkt_num);
    
    return 0;
}
