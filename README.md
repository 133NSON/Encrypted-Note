出给某次银行内部AWD比赛的题目，记录一下
题目的docker配置在目录 `env` 中，使用 `docker-compose up` 启动docker
题目的二进制附件为 `env/bin/note`

## 题目名称

Encrypted Note

### 题目类型

AWD PWN

### 题目分值桶

1000

### 提示

- 加入了AES加密保护，需要绕过AES
- AES的密钥地址与libc基址的偏移为0x4f7000，加密后的flag地址与libc基址的偏移为-0x2c000（**视情况上这条hint**）

### 作者

133NSON

### 备注

### 题目描述

Mai同学学习了一些密码学知识后，尝试编写了一个笔记加密系统。你能帮她测试一下这个系统吗？

