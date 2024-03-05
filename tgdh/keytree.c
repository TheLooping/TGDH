#include "keytree.h"

void fprintf_log(FILE *file, const char *format, ...){

    va_list args;
    va_start(args, format);
    //
    // 获取当前时间
    clock_gettime(CLOCK_REALTIME, &ts);
    // 将纳秒级别的时间戳转换为毫秒级别
    milliseconds = ts.tv_nsec / 1000000;
    // 将毫秒级别的时间戳格式化为字符串
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&ts.tv_sec));    
    // 在时间字符串后面加上毫秒
    sprintf(time_str + strlen(time_str), ".%03ld", milliseconds);


    //
    // time(&rawtime);
    // timeinfo = localtime(&rawtime);
    // // 将时间戳格式化为字符串
    // strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    // 写入时间戳到文件
    fprintf(file, "[%s]", time_str);
    vfprintf(file, format, args);

    fflush(file);
    
    va_end(args);
}


// 根据节点ID查找父节点ID
int findParentID(int nodeID) {
    if (nodeID == 0) return -1; // 根节点没有父节点
    return (nodeID - 1) / 2;
}
// 根据节点ID查找兄弟节点ID
int findSiblingID(int nodeID) {
    if (nodeID == 0) return -1; // 根节点没有兄弟节点
    if (nodeID % 2 == 0) return nodeID - 1; // 偶数节点的左兄弟节点ID
    else return nodeID + 1; // 奇数节点的右兄弟节点ID
}
// 根据节点ID查找左孩子节点ID
int findLeftChildID(int nodeID) {
    return nodeID * 2 + 1;
}
// 根据节点ID查找右孩子节点ID
int findRightChildID(int nodeID) {
    return nodeID * 2 + 2;
}
// 根据层数返回当前层的最左侧节点ID
int findLeftID(int level) {
    return pow(2, level) - 1;
}
int findRightID(int level) {
    return pow(2, level + 1) - 2;
}
// 根据节点ID查找当前节点所在层数
int findLevel(int nodeID) {
    int level = 0;
    while (nodeID > 0) {
        nodeID = findParentID(nodeID);
        level++;
    }
    return level;
}

// 判断节点A是否在节点B为根的子树中
int isSubTree(int nodeA, int rootB) {
    int levelA = findLevel(nodeA);
    int levelB = findLevel(rootB);
    if (levelA < levelB) return 0;
    int parentID = nodeA;
    while (levelA > levelB) {
        parentID = findParentID(parentID);
        levelA--;
    }
    if (parentID == rootB) return 1;
    else return 0;
}

// 根据节点A在节点B为根的子树中的位置获取ID
int findSubTreeID(int root, int level, int index) {
    return pow(2, level) * (root + 1) - 1 + index;
}

// 计算节点A在节点B为根的子树中的位置
void findSubTreePos(int nodeA, int rootB, int *level, int *index) {
    if (isSubTree(nodeA, rootB) == 0) {
        fprintf_log(log_file,"Error: findSubTreePos wrong!.\n");
        return;
    }
    int parentID = nodeA;
    *level = 0;
    while(parentID != rootB) {
        parentID = findParentID(parentID);
        (*level)++;
    }
    int leftID = findSubTreeID(rootB, *level, 0);
    *index = nodeA - leftID;
}


// 返回当前树中最低层中最右侧节点ID 逐层检查最右侧
// 递归所有子节点，找到第一个flag为2的节点
int findLowestRightID(int nodeID) {    
    int level ;
    int leftID;
    int rightID;
    for (level = 0; level <= TREE_HEIGHT - findLevel(nodeID); level++) {
        leftID = findSubTreeID(nodeID, level, 0);
        rightID = findSubTreeID(nodeID, level, pow(2, level) - 1);
        for(int index = rightID; index >= leftID; index--) {
            if (kt_ctx->nodes[index].flag == 2) {
                return index;
            }
        }
    }
    return -1;
}

// 计算离开sponsor：根据节点ID查找兄弟节点的子树中最低层的最右侧成员节点ID
int findLeaveSponsorID(int nodeID) {
    // 兄弟节点是否为叶子节点
    int siblingID = findSiblingID(nodeID);
    if (kt_ctx->nodes[siblingID].flag == 2) {
        return siblingID;
    } else {
        return findLowestRightID(siblingID);
    }
}
// 计算加入sponsor：查找根节点的树中最低层的最右侧成员节点ID
int findJoinSponsorID() {
    return findLowestRightID(0);
}



// 根据key生成blind_key
BIGNUM *generateBlindKey(BIGNUM *key, BIGNUM *alpha, BIGNUM *p){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *blind_key = BN_new();
    BN_mod_exp(blind_key, alpha, key, p, ctx);
    return blind_key;
}

// 根据节点的key和兄弟节点的blind_key生成父节点的key
BIGNUM *generateParentKey(BIGNUM *self_key, BIGNUM *sibling_blind_key, BIGNUM *p){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *parent_key = BN_new();
    BN_mod_exp(parent_key, sibling_blind_key, self_key, p, ctx);
    return parent_key;
}


// 更新kt_ctx中对应节点的blind_key
void updateNodeKey(int nodeID, BIGNUM *blind_key){
    if(kt_ctx->nodes[nodeID].blind_key == NULL){
        kt_ctx->nodes[nodeID].blind_key = BN_new();
        BN_copy(kt_ctx->nodes[nodeID].blind_key, blind_key);
    }
    else{
        BN_copy(kt_ctx->nodes[nodeID].blind_key, blind_key);
    }
    kt_ctx->nodes[nodeID].is_update = 1;   
}

// 更新路径上的节点的key和blind_key
// 逻辑：从当前节点开始，递归计算父节点的key和blind_key，更新到ctx中
void updatePathKey(int nodeID, BIGNUM *key){        
    int parentID = findParentID(nodeID);
    if (parentID == -1) return;
    BIGNUM *sibling_blind_key = kt_ctx->nodes[findSiblingID(nodeID)].blind_key;
    BIGNUM *parent_key = generateParentKey(key, sibling_blind_key, kt_ctx->p);
    BIGNUM *parent_blind_key = generateBlindKey(parent_key, kt_ctx->alpha, kt_ctx->p);
    updateNodeKey(parentID, parent_blind_key);
    updatePathKey(parentID, parent_key);
}

// 更新群组密钥 上下文信息、根节点信息、节点状态
void updateGroupKey(){
    // 更新上下文信息
    kt_ctx->rounds++;
    // 更新根节点(路径信息)
    updatePathKey(key_self->id, key_self->self_key);    
    // 更新节点状态
    for (int i = 0; i < NODE_NUM; i++) {
        if (kt_ctx->nodes[i].is_update == 1) {
            kt_ctx->nodes[i].is_update = 0;
        }
    }
    // fprintf_log(log_file, "%dth rekey:%s\n", kt_ctx->rounds,BN_bn2hex(kt_ctx->nodes[0].blind_key));
}
// 根据前后ID移动节点
void moveNode(int oldID, int newID){
    memcpy(&(kt_ctx->nodes[newID]), &(kt_ctx->nodes[oldID]), sizeof(keytree_node));
    memset(&(kt_ctx->nodes[oldID]), 0, sizeof(keytree_node));
    kt_ctx->nodes[oldID].id = oldID;
    kt_ctx->nodes[newID].id = newID;
    // leaf节点移动后仍然是leaf节点，node节点移动后仍然是node节点

}

// 根据前后ID移动子树
void moveSubTree(int old_root, int new_root){

    int level;
    int oldID;
    int newID;
    int leftID;
    int rightID;
    for (level = 0; level <= TREE_HEIGHT - findLevel(old_root); level++) {
        leftID = findSubTreeID(old_root, level, 0);
        rightID = findSubTreeID(old_root, level, pow(2, level) - 1);
        fprintf_log(log_file,"leftID:%d ;rightID:%d \n",leftID,rightID);
        for(int ID = rightID; ID >= leftID; ID--) {
            if (kt_ctx->nodes[ID].flag != 0)
            {
                oldID = ID;
                newID = findSubTreeID(new_root, level, ID - leftID);
                fprintf_log(log_file, "move %d to %d \n", oldID, newID);
                moveNode(oldID, newID);
            }          
        }
    }
}








// 新节点加入：sponsor调用此函数
// 逻辑：1sponsor信息移动到左孩子节点 2新节点加入右孩子节点 3补全原位置信息 4计算路径上的节点的blind_key
void joinTree(keytree_node *node, BIGNUM *key){
    

    int joinSponsorID = findJoinSponsorID();
    int leftChildID = findLeftChildID(joinSponsorID);
    int rightChildID = findRightChildID(joinSponsorID);


    // sponsor信息移动到左孩子节点
    moveNode(joinSponsorID, leftChildID);
    // 新节点加入右孩子节点
    kt_ctx->nodes[rightChildID].flag = 2;
    kt_ctx->nodes[rightChildID].is_update = 1;
    kt_ctx->nodes[rightChildID].addr = node->addr;
    kt_ctx->nodes[rightChildID].blind_key = BN_new();    
    BN_copy(kt_ctx->nodes[rightChildID].blind_key, node->blind_key);
    // 补全原位置信息    
    memset(&kt_ctx->nodes[joinSponsorID], 0, sizeof(keytree_node));
    kt_ctx->nodes[joinSponsorID].id = joinSponsorID;
    kt_ctx->nodes[joinSponsorID].flag = 1;


    // 更新自己信息
    key_self->id = leftChildID;

    // 计算sponsor新路径上的节点的blind_key
    updateGroupKey();
    // 释放资源
    BN_free(node->blind_key);
    free(node);
}


// 节点加入：所有节点调用此函数
// 逻辑：1新节点加入 2移动节点位置
void nodeJoinTree(keytree_node *node){
    int joinSponsorID = findJoinSponsorID();    
    int leftChildID = findLeftChildID(joinSponsorID);
    int rightChildID = findRightChildID(joinSponsorID);
    // 判断node的位置是否正确
    // if (kt_ctx->nodes[leftChildID].flag != node->id) {
    //     fprintf_log(log_file,"Error: nodeJoinTree wrang!.\n");
    //     return;
    // }
    // 新节点加入
    kt_ctx->nodes[rightChildID].flag = 2;
    kt_ctx->nodes[rightChildID].is_update = 0;
    kt_ctx->nodes[rightChildID].addr = node->addr;
    kt_ctx->nodes[rightChildID].blind_key = BN_new();
    BN_copy(kt_ctx->nodes[rightChildID].blind_key, node->blind_key);

    // 移动节点位置
    moveNode(joinSponsorID, leftChildID);

 
    memset(&kt_ctx->nodes[joinSponsorID], 0, sizeof(keytree_node));
    kt_ctx->nodes[joinSponsorID].id = joinSponsorID;
    kt_ctx->nodes[joinSponsorID].flag = 1;

}

// 节点离开：sponsor调用此函数
// 逻辑：1离开节点信息清空 2兄弟节点及其子树移动到父节点位置 3移动后的sponsor更新自己的key 4sponsor计算路径上的节点的blind_key
void leaveTree(int nodeID, BIGNUM *key){
    int parentID = findParentID(nodeID);
    int siblingID = findSiblingID(nodeID);
    int leaveSponsorID = findLeaveSponsorID(nodeID);
    // 离开节点信息清空
    memset(&kt_ctx->nodes[nodeID], 0, sizeof(keytree_node));
    kt_ctx->nodes[nodeID].id = nodeID;
    // 兄弟节点及其子树移动到父节点位置
    moveSubTree(siblingID, parentID);
    key_self->id  = findLowestRightID(parentID);


    // 更新自己的密钥和盲化密钥
    BN_rand(key_self->self_key, KEY_LEN * 8, 0, 0);
    BN_free(kt_ctx->nodes[key_self->id].blind_key);
    kt_ctx->nodes[key_self->id].blind_key = generateBlindKey(key_self->self_key,kt_ctx->alpha,kt_ctx->p);
    
    // sponsor计算路径上的节点的blind_key
    updateGroupKey();
}

// 节点离开：所有节点调用此函数
// 逻辑：1节点离开 2移动节点位置
void nodeLeaveTree(int nodeID){
    int parentID = findParentID(nodeID);
    int siblingID = findSiblingID(nodeID);
    // 节点离开
    memset(&kt_ctx->nodes[nodeID], 0, sizeof(keytree_node));
    kt_ctx->nodes[nodeID].id = nodeID;
    // 移动节点位置
    fprintf_log(log_file,"move sub tree: %d to %d\n",siblingID, parentID);
    moveSubTree(siblingID, parentID);    
    // 更新自己信息 自己在子树中，则需要更新自己的ID；否则不需要更新
    if (isSubTree(key_self->id, siblingID)) {
        int level;
        int index;
        findSubTreePos(key_self->id, siblingID, &level, &index);
        key_self->id = findSubTreeID(parentID, level, index);
    }
}



void printSpaces(char **info, int n) {
    for (int i = 0; i < n; i++) {
        sprintf(*info, " ");
        *info += 1; // 移动到下一个位置
    }
}
void printfLine(char *info,int layer, int level){
    int space = pow(2 , (layer - level ));
    int width = pow(2 , (layer - level));
    int left = findSubTreeID(0,level,0);
    int right = findSubTreeID(0, level, pow(2, level) - 1);
    int num = right - left + 1;
    for(int i = 0 ;i < num; i++){
        if(kt_ctx->nodes[left + i].flag != 0){
            sprintf(info,"%*d", width, left + i);
            info += width;
        }
        else{
            printSpaces(&info,width);
        }        
        printSpaces(&info, space);
    }
    sprintf(info, "\n");
}


void printfTree(){
    int layer = TREE_HEIGHT;
    char *info = malloc(256);
    char *x = info;
    memset(info,0,sizeof(info));
    fprintf_log(log_file, "%dth key tree structure:    (alpha:%s; p:%s)\n",kt_ctx->rounds, BN_bn2hex(kt_ctx->alpha), BN_bn2hex(kt_ctx->p));
    for (int i = 0; i <= layer; i++) {
        printfLine(info,layer,i);
        info = x;
        fprintf_log(log_file, "%s", info);
        memset(info,0,sizeof(info));
    }
        
    for (int i = 0; i < NODE_NUM; i++) {
        if(kt_ctx->nodes[i].flag != 0){
            fprintf_log(log_file, "nodes BK[%d]:%s\n", i, BN_bn2hex(kt_ctx->nodes[i].blind_key));
        }
    }
    fprintf_log(log_file, "self_key:(%d)%s\n", key_self->id, BN_bn2hex(key_self->self_key));
    fprintf(log_file,"\n\n");
}







