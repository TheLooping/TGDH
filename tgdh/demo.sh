#!/bin/bash
pkill -f "tgdh_test*"

rm -f *.txt
rm /root/tgdh_server/*.txt
rm -f tgdh_test*
gcc -g /root/tgdh/*.c -o /root/tgdh/tgdh_test -lssl -lcrypto -lm -lc -lpthread
gcc -g /root/tgdh_server/*.c -o /root/tgdh_server/tgdh_server -lssl -lcrypto -lm -lc -lpthread


# 原始文件名
original_file="tgdh_test"
n=12
# 循环n次
for ((i=0; i<n; i++))
do
    # 构建新文件名
    new_file="tgdh_test$i"    
    # 复制文件并重命名
    cp "$original_file" "$new_file"
done


gnome-terminal --tab -t "tgdh_server" -- bash -c "cd ../tgdh_server;./tgdh_server;exec bash"

# 循环n次
for ((i=0; i<n; i++))
do
    # 打开终端窗口，执行命令
    # gnome-terminal -t "999$i" -- bash -c "./tgdh_test$i 192.168.140.130 999$i;exec bash"
    gnome-terminal  --tab -t "999$i" -- bash -c "./tgdh_test$i 192.168.140.130 999$i"
done

