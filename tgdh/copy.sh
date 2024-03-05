#!/bin/bash

# 原始文件名
original_file="test"

# 循环10次
for ((i=0; i<10; i++))
do
    # 构建新文件名
    new_file="test$i"
    
    # 复制文件并重命名
    cp "$original_file" "$new_file"
done
