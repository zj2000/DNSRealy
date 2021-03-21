#ifndef DNS_HEADER
#define DNS_HEADER

#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include<process.h>
#include<time.h>
#pragma comment(lib,"Ws2_32.lib")
#pragma warning(disable:4996 6385 6386)

#define BOOL int
#define TRUE 1
#define FALSE 0

#define PORT 53		//本地名字服务器监听端口号
#define IN_CLASS 1
#define BUF_SIZE 1024// ??缓存区大小

#define DNS_HEADER_LEN 12		//dns头部长度
#define MAX_HOST 1010			//储存本机资源每个部分数量上限
#define MAX_CACHED 1000			//缓存上层dns回应资源每个部分数量上限
#define MAX_REQUEST 2000		//最大请求量
#define CACHED_TTL 60
#define REQUEST_TTL 60
#define UPPER_DNS "192.168.43.1"	//上层dns------------------------待定！！！
#define ERROR_IP_ADDR "0.0.0.0"	//被拦截的错误地址，返回域名不存在
#define UPPERPORT(i) (i + 50000)     //与上层DNS通信的本机端口号转换（由请求处理线程id->端口号，50000开始一般为未分配端口号
#define UPPER_TIMEOUT 1000//等待上层回应超时

#define ADDR_NORMAL 1	//检索结果为普通IP地址
#define ADDR_ERROR 2	//报错，检索结果为0.0.0.0
#define ADDR_NOT_FOUND 3//未检索到域名，像本地DNS服务器查询

//查询类型
#define A 1
#define NS 2
#define MX 15
#define CNAME 5
#define PTR 12
#define AAAA 28

//定义DNSHeader
#pragma pack(push, 1)  // 按一字节方式对齐
typedef struct
{
	UINT16 id;		  //16位,该值由发出DNS请求的程序生成，DNS服务器在响应时会使用该ID，这样便于请求程序区分不同的DNS响应。

	//位域排序类似于小段方式
	unsigned char rd : 1;     //1位，期望使用递归解析 (Recursion desired),如果该位为0，表示使用迭代查询方式
	unsigned char tc : 1;     //1位，被截断的报文(Truncated):当响应的总长度超512字节时，只返回前512个字节
	unsigned char aa : 1;     //1位，权威答案(Authoritative answer),表示响应的服务器是否是权威DNS服务器。只在响应消息中有效。
	unsigned char opCode : 4; //4位，0:标准查询 ,指示请求的类型，有请求发起者设定，响应消息中复用该值。 1:反向查询 , 2:服务器状态请求
	unsigned char qr : 1;     //1位，0表示查询请求报文，1表示响应报文
	
	unsigned char rCode : 4;  //4位，响应码(Response coded)，仅用于响应报文
	unsigned char z : 3;      //3位，必须为0，保留字段
	unsigned char ra : 1;     //1位，递归可用(Recursion Available),该值在响应消息中被设置或被清除，以表明服务器是否支持递归查询。

	UINT16 qdCount;   //question section的问题个数，16位
	UINT16 anCount;   //answer section的RR(Resource Record)个数，16位
	UINT16 nsCount;   //authority records section的RR个数，16位
	UINT16 arCount;   //additional records section的RR个数，16位
}DNSHeader;
#pragma pack(pop)  //恢复原来的对齐方式


//Question部分的每一个实体的格式
typedef struct
{
	char* qName;	//字节数不定，以0x00作为结束符。表示查询的主机名。主机名被"."号分割成了多段标签。在QNAME中，每段标签前面加一个数字，表示接下来标签的长度。
	UINT16 qType;	//占2个字节。表示RR类型
	UINT16 qClass;	//占2个字节。表示RR分类
}QUESTION;


//Answer、Authority、Additional部分格式一致，每部分都由若干实体组成，每个实体即为一条RR
typedef struct
{
	char* name;
	UINT16 type;	//占2个字节。表示RR的类型，如A、CNAME、NS等
	UINT16 rclass;	//占2个字节。表示RR的分类
	UINT32 ttl;		//占4个字节。表示RR生命周期，即RR缓存时长，单位是秒
	UINT16 rdLength;//占2个字节。指定RDATA字段的字节数
	char* rData;
}RR;

//DNS包：头部，问题，回应
typedef struct DnsPacket
{
	DNSHeader* header;

	QUESTION* queries;//查询问题区域，动态分配的数组个数由qdCount决定
	RR* answers;	//回答问题区域，动态分配的数组个数由anCount决定
	RR* authority;	//权威名称服务器区域，动态分配的数组个数由nsCount决定
	RR* additional;	//附加信息区域,动态分配的数组个数由arCount决定

}DNSPacket;

//DNS请求（存放在请求池里）
typedef struct DnsRequest
{
	BOOL isServed;
	int seq;//序号，打印时输出
	SYSTEMTIME systemTime;//系统时间,打印调试信息时输出
	int ttl;
	int oldID;
	int newID;
	DNSPacket* packet;
	SOCKADDR_IN clientAddr;
	int clientAddrLen;
}DNSRequest;

//DNS请求池，存放请求
typedef struct RequestPool//请求池节点，执行完毕删除节点
{
	BOOL isAvailable;//初始为TRUE当有线程开始处理时变为FALSE
	DNSRequest* requestPtr;
	struct RequestPool* nextRequestPtr;
}REQUESTPool;
typedef REQUESTPool* REQUESTPoolPtr;

//本机存储资源
typedef struct Host
{
	int type;//资源类型 ADDR_NORMAL / ADDR_ERROR
	uint32_t ipAddress;//IP地址
	char* domainName;//域名
	struct Host* nextHostPtr;
}HOST;
typedef HOST* HOST_PTR;

//从上层DNS获取的资源链表结点
typedef struct Cached
{
	int ttl;
	uint32_t ipAddress;//IP地址
	char* domainName;//域名
	char* cName;//别名
	struct Cached* nextCachedPtr;
}CACHED;
typedef CACHED* CACHED_PTR;


extern HOST_PTR hostTableFront[36]; //分别代表a-z、0-9开头的域名
extern HOST_PTR hostTableRear[36]; //开头a-z、0-9域名资源尾指针
extern CACHED_PTR cachedTableFront[36]; //分别代表a-z、0-9开头的域名
extern CACHED_PTR cachedTableRear[36]; //开头a-z、0-9域名资源尾指针
extern int hostCount[36];//本机资源每个部分的资源数
extern int cachedCount[36];//缓存资源每个部分的资源数
extern BOOL isCachedOperateAvailable;//同时只能有一个线程对cached资源进行改写，相当于mutex
extern REQUESTPool* requestPool;//请求池头部
extern int requestCount;//请求池请求数目
extern BOOL isPoolOperateAvailable;//同时只能有一个线程对请求池资源进行改写，相当于mutex
extern SOCKET serverSocket;//服务器与客户端通信套接字
extern int newIdDistribute;//新分配id，除余MAX_REQUEST最大请求数

void InitHostTable();//初始化资源列表
void InitCachedTable();//初始化缓存资源列表
void InputHostFile();//读入资源
void AddHostToTable(HOST_PTR currentHost, char initial);//将资源添加到列表里
int InitDNSServer();//启动WSA加载套接字库,创建服务套接字并绑定端口

DNSHeader* GetHeaderStruct(char* headerStartLoc, char** nextStartLoc);	//dns头字符转换为dns头结构体
void MakeQueryStruct(QUESTION* packetQuery, char* queryStartLoc, char** nextStartLoc);	//dns请求段字符转换为dns请求段结构体
void MakeRRStruct(RR* packetResponse, char* responseStartLoc, char* headerStartLoc, char** nextStartLoc);	//dns回应段字符转换为dns回应段结构体
char* GetHeaderString(DNSHeader* header);		//dns头结构体转换为dns头字符
char* GetQueryString(QUESTION* query);			//dns请求段结构体转换为dns请求段字符
char* GetRRString(RR* response);				//dns回应段结构体转换为dns回应段字符
DNSPacket* MakeDNSPacket(char* recvString);		//把dns字符串变成dns包结构体用以发送
char* GetDNSPacketString(DNSPacket* packet, int* len);	//把dns包结构体变成字符串用以发送

void HandleRequestThread(void* lpvoid);	//处理dns收到的请求
void HandleReplyThread(void* lpvoid);	//处理上层dns的回应
int AddDNSRequestToPool(DNSRequest*);	//将新收到的客户端请求加入到请求池里面，返回当前请求数目，返回-1请求池已满添加失败
DNSRequest* GetDNSRequest();			//从请求池里面获取可以执行的请求
DNSRequest* FinishDNSRequestInPool(int);//在请求池中标记请求已完成
void HandleReplyPacket(char*);		//分析上层dns回应，添加cache的地址
int getAddrStatus(char* addr, UINT32 ipAddr[30], int* count);//获取此地址的状态：blocked cashed notfound
int getCNameStatus(char* name, char** domainName);
DNSPacket* formDNSPacket(DNSPacket* clientPacket, UINT32 ipAddr[30], int addrStatus, int count);//根据地址blocked或cached的情况进行DNS包结构体的创建
DNSPacket* FormCNAMEPacket(DNSPacket* clientPacket, char* domainName);
void FlushDnsCacheTTLThread();		//定期缩短cache地址的剩余有效时间
void FlushDNSRequestTTLThread();	//定期缩短请求池里面请求的剩余有效时间
int GetTableSeq(char initial);		//返回数组下标

void PrintDebugInfo(DNSRequest* req);
void PrintRecvPacketInfo(char* recv, int len, DNSHeader* header);
char* GetNormalDomainName(char* DNSDomainName);//把dns形式的域名转换成常规形式的域名
char* GetDNSDomainName(char* normalDomainName);//把常规形式的域名转换成dns形式的域名

void FreePacketSpace(DNSPacket* packet);//释放dns包的分配空间，函数结束时packet指向NULL

#endif // !DNS_HEADER