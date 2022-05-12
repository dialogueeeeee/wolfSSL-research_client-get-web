# About

## 概述
这里是环境配置的介绍。

## 开发环境
- 开发语言：``C`` 
- 开发平台：``Ubuntu 20.04``
- 编译工具：``gcc V9.3.0``
- SSL 平台：``WolfSSL``
## 环境搭建
### 编译环境搭建
```
sudo apt-get update
sudo apt-get install gcc
````
### `wolfssl` 环境

- 在 https://www.wolfssl.com/download 下载 ``wolfssl`` 和 ``tiny-curl`` 最新版本。（当前为 ``wolfssl-5.0.0.zip`` 和 ``tiny-curl-7.72.0.zip``）
- 安装 wolfssl
``` shell
$ unzip wolfssl-5.0.0.zip 
$ cd wolfssl-5.0.0 
$ ./configure --prefix /usr/local/wolfssl 
$ make 
$ sudo make install 

$ cd /usr/local/wolfssl/bin 
$./wolfssl-config --version 
5.0.0
```

### `wolfSSL API` 环境
``` shell
sudo apt-get install libwolfssl-dev
```
