/*
Author：DYL
Environment: Linux(Ubuntu 20.3)
Introduce:     通信流程如下
               1、初始化，解析url资源，创建socket 连接，绑定ssl
               2、发送 http 请求
               3、获取请求返回的状态码
               4、获取请求返回的数据
               5、销毁动态申请的内存资源
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/ssl.h>            //wolfssl 转 openssl的兼容层

 
#define HTTP_REQ_LENGTH          512            // http 请求头
#define HTTP_RESP_LENGTH         20480          // http 响应头
 
typedef struct
{
    int sock_fd;
    WOLFSSL_CTX* ssl_ctx;
    WOLFSSL* ssl;

    //url 解析出来的信息
    char *host;                 // 主机地址
    char *path;                 // 路径
    int port;                   // 端口号
} https_context_t;              // https 内容结构体
 
static int https_init(https_context_t *context,const char* url);
static int https_uninit(https_context_t *context);
static int https_read(https_context_t *context,void* buff,int len);
static int https_write(https_context_t *context,const void* buff,int len);
static int https_get_status_code(https_context_t *context);
static int https_read_content(https_context_t *context,char *resp_contet,int max_len);
 
// http 请求头信息
static char https_header[] =
    "GET %s HTTP/1.1\r\n"
    "Host: %s:%d\r\n"
    "Connection: Close\r\n"
    "Accept: */*\r\n"
    "\r\n";
 
static char http_req_content[HTTP_REQ_LENGTH] = {0};                        // http 请求头
static char https_resp_content[HTTP_RESP_LENGTH+1] = {0};                   // https 相应内容
 
static int create_request_socket(const char* host,const int port)           // 创建请求套件函数
{
    int sockfd;
    struct hostent *server;             // hostent 结构体，包含在 #include<netdb.h> 和 #include<sys/socket.h> 中
    struct sockaddr_in serv_addr;       // sockaddr_in 结构体，包含在 #include<netinet/in.h> 或 #include <arpa/inet.h> 中                                          
 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);   // socket 函数，详见文件结束 知识点 部分，包含在 <sys/socket.h> 中 // 创建 TCP 套接字
    if (sockfd < 0)     
    {
        printf("[http_demo] create_request_socket create socket fail.\n");  // 创建套接字失败
        return -1;
    }
 
    /* lookup the ip address */
    server = gethostbyname(host);       // gethostbyname() 函数，包含在 #include <netdb.h> 和 #include <sys/socket.h> 中
    if(server == NULL)
    {
        printf("[http_demo] create_request_socket gethostbyname fail.\n");  // 用域名或主机名获取 IP 地址失败
        close(sockfd);                                                      // 断开已经建立的套接字
        return -1;
    }
 
    memset(&serv_addr,0,sizeof(serv_addr));     // 复制字符 0（一个无符号字符）到参数 serv_addr 所指向的字符串的前 sizeof(serv_addr) 个字符，详见知识点   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);           // HBO -> NBO 即 主机字节序 -> 网络字节序
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
 
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
    {
        printf("[http_demo] create_request_socket connect fail.\n");
        close(sockfd);
        return -1;
    }
    return sockfd;
}
 
/**
 * @brief https_parser_url  解析出 https 中的域名、端口和路径
 * @param url   需要解析的url
 * @param host  解析出来的域名或者ip
 * @param port  端口，没有时默认返回443
 * @param path  路径，指的是域名后面的位置
 * @return
 */
static int https_parser_url(const char* url,char **host,int *port,char **path)
{
    if(url == NULL || strlen(url) < 9 || host == NULL || path == NULL)  // url 或 域名(ip) 或 路径 为空 / 或 url 长度小于 9（即 https:// 长度为 8 ），则返回错误 null
    {
         printf("[https_demo] url or host or path is null.\n");
         return -1;
    }
 
    //判断是不是 https://
    int i = 0;
    char https_prefix[] = "https://";
    for(i=0;i<8;i++)                                                    // 遍历前 8 个字符串，若不为 https:// 开头，则返回 illegal
    {
        if(url[i] != https_prefix[i])
        {
            printf("[https_demo] illegal url = %s.\n",url);
            return -1;
        }
    }
 
    const char *temp = url+i;
    while(*temp != '/')                                                 // 遍历 temp 当其不为 '/' 时执行，即 判断 https:// 之后的内容
    {
        if(*temp == '\0')                                               // 判断 https:// 之后的内容是否为空（c 语言中 ！='\0'.就是运行到字符串结尾时结束）
        {
            printf("[https_demo] illegal url = %s.\n",url);             // 若 https:// 之后的内容为空，返回 illegal
            return -1;
        }
        temp++;
    }
 
    const char *host_port = url+i;                                       
    while(*host_port != ':' && *host_port != '/')                       // 找到 : 或者 / 结束
    {
        host_port ++;                                                   // 计算 有效地址 长度
    }
 
    int host_len = host_port-url-i;                                     // 计算 减掉 https:// 之后的长度
    int path_len = strlen(temp);                                        // 计算整个 url 长度
    char *host_temp = (char *)malloc(host_len + 1);                     // 多一个字符串结束标识 \0
    if(host_temp == NULL)
    {
        printf("[https_demo] malloc host fail.\n");                     //
        return -1;
    }
    if(*host_port++ == ':')                                             //url 中有端口
    {
        *port = 0;
        while(*host_port !='/' && *host_port !='\0')                    //十进制字符串转成数字
        {
            *port *= 10;
            *port += (*host_port - '0');
            host_port ++;
        }
    }
    else
    {
        *port = 443;
    }
 
    char *path_temp = (char *)malloc(path_len + 1);                     //多一个字符串结束标识 \0
    if(path_temp == NULL)
    {
        printf("[https_demo] malloc path fail.\n");
        free(host_temp);
        return -1;
    }
    memcpy(host_temp,url+i,host_len);               // memcpy() 即 memory copy 缩写，意为内存复制   // void *memcpy(void *dest, const void *src, size_t n);
    memcpy(path_temp,temp,path_len);                // 它的功能是从src的开始位置拷贝n个字节的数据到dest。如果dest存在数据，将会被覆盖。memcpy函数的返回值是dest的指针。memcpy函数定义在string.h头文件里。
    host_temp[host_len] = '\0';                     // c 语言字符串结尾
    path_temp[path_len] = '\0';                     // c 语言字符串结尾
    *host = host_temp;
    *path = path_temp;
    return 0;
}
 
static int https_init(https_context_t *context,const char* url)
{
    if(context == NULL)
    {
        printf("[https_demo] init https_context_t is null.\n");                     // 解析出来的 https context 为空 返回 null
        return -1;
    }
 
    if(https_parser_url(url,&(context->host),&(context->port),&(context->path)))    // 若 https_parser_url 函数 return -1 则返回 fail （详见 https_parser_url 函数）
    {
        printf("[https_demo] https_parser_url fail.\n");                            // https 请求 或 url 参数错误
        return -1;
    }
 
    context->sock_fd = create_request_socket(context->host,context->port);          // 若 create_request_socket 函数 return -1 则返回 fail （详见 create_request_socket 函数）
    if(context->sock_fd < 0)
    {
        printf("[https_demo] create_request_socket fail.\n");                       // 创建请求套接字失败
        goto https_init_fail;
    }


// wolfSSL_CTX_new() 创建会话环境
    context->ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_method());

    if(context->ssl_ctx == NULL)
    {
        printf("[https_demo] WolfSSL_CTX_new fail.\n");                                 // 申请 SSL 会话环境失败
        goto https_init_fail;
    }
// 强制服务器端不加载 CA
    wolfSSL_CTX_set_verify(context->ssl_ctx, SSL_VERIFY_NONE, 0);
// wolfSSL_new() 申请 SSL 套接字
    context->ssl = wolfSSL_new(context->ssl_ctx);

    if(context->ssl == NULL)
    {
        printf("[https_demo] SSL_new fail.\n");                                     // 申请一个 SSL 套接字失败
        goto https_init_fail;
    }


 // wolfSSL_set_fd() 绑定读写套接字             
    if(wolfSSL_set_fd(context->ssl,context->sock_fd) != SSL_SUCCESS)                                 // 将 SSL 与 TCP socket 连接
    {
        printf("[https_demo] WolfSSL_set_fd fail \n");
        goto https_init_fail;
    }     

 // wolfSSL_connect() 完成 SSL 握手
    if(wolfSSL_connect(context->ssl) != SSL_SUCCESS)
    {
        printf("[https_demo] WolfSSL_connect fail.\n");                                 // SSL 握手失败
        goto https_init_fail;
    }
    return 0;

https_init_fail:
    https_uninit(context);                                                          // 跳转到 https_uninit() 函数，表示 https 初始化失败
    return -1;
}
 
static int https_read(https_context_t *context,void* buff,int len)                  // SSL_read() 函数，详见知识点
{
    if(context == NULL || context->ssl == NULL)                                     
    {
        printf("[https_demo] read https_context_t or ssl is null.\n");
        return -1;
    }

    return wolfSSL_read(context->ssl,buff,len);
}
// 进行数据传输阶段 
static int https_write(https_context_t *context,const void* buff,int len)           // 当 SSL 握手完成之后，就可以进行安全的数据传输了
{
    if(context == NULL || context->ssl == NULL)
    {
        printf("[https_demo] write https_context_t or ssl is null.\n");
        return -1;
    }

    return wolfSSL_write(context->ssl,buff,len);
}
 
static int https_get_status_code(https_context_t *context)
{
    if(context == NULL || context->ssl == NULL)
    {
        printf("[https_demo] get status https_context_t or ssl is null.\n");
        return -1;
    }
    int ret;
    int flag =0;
    int recv_len = 0;
    char res_header[1024] = {0};
    while(recv_len<1023)
    {

        ret = wolfSSL_read(context->ssl, res_header+recv_len, 1);

        if(ret<1)  // recv fail
        {
            break;
        }
        //找到响应头的头部信息, 两个"\r\n"为分割点
        if((res_header[recv_len]=='\r'&&(flag==0||flag==2))||(res_header[recv_len]=='\n'&&(flag==1||flag==3)))
        {
            flag++;
        }
        else
        {
            flag = 0;
        }
        recv_len+=ret;
        if(flag==4)
        {
            break;
        }
    }
    //printf("[http_demo] recv_len=%d res_header = %s.\n",recv_len,res_header);
    /*获取响应头的信息*/
    int status_code = -1;
    char *pos = strstr(res_header, "HTTP/");                                        // strstr() 函数，作用是返回字符串中首次出现子串的地址，详见知识点
    if(pos)
    {
        sscanf(pos, "%*s %d", &status_code);                                        // 返回状态码，详见 https://www.runoob.com/http/http-status-codes.html
    }
    return status_code;
}
 
static int https_read_content(https_context_t *context,char *resp_contet,int max_len)   // 读取 网页内容
{
    if(context == NULL || context->ssl == NULL)                                         
    {
        printf("[https_demo] read content https_context_t or ssl is null.\n");
        return -1;
    }
    int ret ;
    int recv_size = 0;
    while(recv_size < max_len)                                                          
    {

    ret = wolfSSL_read(context->ssl,resp_contet + recv_size,max_len-recv_size);

       if(ret < 1)
       {
           break;
       }
       recv_size += ret;                                                                // 计算返回内容长度
    }
    return recv_size;                                                                   // 返回内容长度
}
 
static int https_uninit(https_context_t *context)                                       // 初始化失败函数，释放内存
{                                                                                       // 当客户端和服务器之间的数据通信完成之后，调用下面的函数来释放已经申请的 SSL 资源
    if(context == NULL)
    {
        printf("[https_demo] uninit https_context_t is null.\n");
        return -1;
    }
 
    if(context->host != NULL)
    {
        free(context->host);
        context->host = NULL;
    }
    if(context->path != NULL)
    {
        free(context->path);
        context->path = NULL;
    }
 
    if(context->ssl != NULL)
    {
        wolfSSL_shutdown(context->ssl);
        context->ssl = NULL;
    }
    if(context->ssl_ctx != NULL)
    {
        wolfSSL_CTX_free(context->ssl_ctx);
        context->ssl_ctx = NULL;
    }
    if(context->sock_fd > 0)
    {
        close(context->sock_fd);
        context->sock_fd = -1;
    }
    return 0;
}
 
int main()
{
    https_context_t https_ct = {0};
    int ret = wolfSSL_library_init();                   
    if (ret != SSL_SUCCESS) {
        printf('failed to initialize wolfSSL Library !');
    }
    else{
        printf("[https_demo] WolfSSL_library_init ret = %d.\n",ret);
    }

    https_init(&https_ct,"https://www.baidu.com/");
 
    ret = snprintf(http_req_content,HTTP_REQ_LENGTH,https_header,https_ct.path,https_ct.host,https_ct.port);
 
    ret = https_write(&https_ct,http_req_content,ret);              // 进行数据传输阶段，使用 https_write() 函数将网页信息写入 ret
    printf("[https_demo] https_write ret = %d.\n",ret);             // 打印 网页信息(ret)
 
    if(https_get_status_code(&https_ct) == 200)                     // HTTP Status Code 返回 200 表示请求成功
    {
       ret = https_read_content(&https_ct,https_resp_content,HTTP_RESP_LENGTH);
       if(ret > 0)
       {
           https_resp_content[ret] = '\0';  //字符串结束标识
           printf("[https_demo] https_write https_resp_content = \n %s.\n",https_resp_content);
       }
    }
    https_uninit(&https_ct);
    return 0;
}
