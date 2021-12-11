# About

## 概述

这是关于 wolfSSL 的技术研究报告。

## wolfSSL API 介绍
- 对于 ``C`` 语言环境下的 ``wolfSSL`` 应用，主要使用 ``wolfSSL`` 的 API ，``wolfSSL`` 的 API 基于 ``C`` 语言编写并包含在 ``<wolfssl/ssl.h>`` 头文件中，可以参考 https://www.wolfssl.com/doxygen/wolfssl_API.html 了解更多接口信息。

- 在 ``./example/wolfssl_https_getWeb.c`` 文件中，使用 ``C`` 语言实现网页内容获取的过程，其中主要用到的 ``wolfSSL`` API 介绍如下。 

### 结构体
```C
WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method);
WOLFSSL* ssl = wolfSSL_new(ctx);
```
### 库函数
``int ret = wolfSSL_library_init();``
- 作用：wolfSSL 库初始化
- 详细参考：https://www.wolfssl.com/doxygen/group__TLS.html#ga20101bd5ed1dde1ea746d57d235a17a1

``ctx = wolfSSL_CTX_new(method);``
- 作用：申请 SSL 会话环境
- 详细参考：https://www.wolfssl.com/doxygen/group__Setup.html#gadfa552e771944a6a1102aa43f45378b5

``ssl = wolfSSL_new(ctx);``
- 作用：申请 SSL 套接字
- 详细参考：https://www.wolfssl.com/doxygen/group__Setup.html#gadfa552e771944a6a1102aa43f45378b5

``wolfSSL_set_fd(ssl, sockfd);``
- 作用：绑定读写套接字
- 详细参考：https://www.wolfssl.com/doxygen/group__Setup.html#ga93af2b070b4397008992b8272b960b55

``wolfSSL_connect(ssl);``
- 作用：完成 SSL 握手
- 详细参考：https://www.wolfssl.com/doxygen/group__IO.html#ga5b8f41cca120758d1860c7bc959755dd

``input = wolfSSL_read(ssl, reply, sizeof(reply));``
- 作用：对套接字的读操作
- 详细参考：https://www.wolfssl.com/doxygen/group__IO.html#ga33732bde756a527d61a32212b4b9a017

``ret = wolfSSL_write(ssl, msg, msgSz);``
- 作用：对套接字的写操作
- 详细参考：https://www.wolfssl.com/doxygen/group__IO.html#ga74b924a81e9efdf66d074690e5f53ef1

``ret = wolfSSL_shutdown(ssl);``
- 作用：关闭 SSL 套接字
- 详细参考：https://www.wolfssl.com/doxygen/group__TLS.html#ga4d8ddcffbe653b7ec26878e34093c048

``wolfSSL_CTX_free(ctx);``
- 作用：关闭 SSL 套接字
- 详细参考：https://www.wolfssl.com/doxygen/group__Setup.html#ga93af2b070b4397008992b8272b960b55
