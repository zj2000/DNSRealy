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

#define PORT 53		//�������ַ����������˿ں�
#define IN_CLASS 1
#define BUF_SIZE 1024// ??��������С

#define DNS_HEADER_LEN 12		//dnsͷ������
#define MAX_HOST 1010			//���汾����Դÿ��������������
#define MAX_CACHED 1000			//�����ϲ�dns��Ӧ��Դÿ��������������
#define MAX_REQUEST 2000		//���������
#define CACHED_TTL 60
#define REQUEST_TTL 60
#define UPPER_DNS "192.168.43.1"	//�ϲ�dns------------------------����������
#define ERROR_IP_ADDR "0.0.0.0"	//�����صĴ����ַ����������������
#define UPPERPORT(i) (i + 50000)     //���ϲ�DNSͨ�ŵı����˿ں�ת�������������߳�id->�˿ںţ�50000��ʼһ��Ϊδ����˿ں�
#define UPPER_TIMEOUT 1000//�ȴ��ϲ��Ӧ��ʱ

#define ADDR_NORMAL 1	//�������Ϊ��ͨIP��ַ
#define ADDR_ERROR 2	//�����������Ϊ0.0.0.0
#define ADDR_NOT_FOUND 3//δ�������������񱾵�DNS��������ѯ

//��ѯ����
#define A 1
#define NS 2
#define MX 15
#define CNAME 5
#define PTR 12
#define AAAA 28

//����DNSHeader
#pragma pack(push, 1)  // ��һ�ֽڷ�ʽ����
typedef struct
{
	UINT16 id;		  //16λ,��ֵ�ɷ���DNS����ĳ������ɣ�DNS����������Ӧʱ��ʹ�ø�ID��������������������ֲ�ͬ��DNS��Ӧ��

	//λ������������С�η�ʽ
	unsigned char rd : 1;     //1λ������ʹ�õݹ���� (Recursion desired),�����λΪ0����ʾʹ�õ�����ѯ��ʽ
	unsigned char tc : 1;     //1λ�����ضϵı���(Truncated):����Ӧ���ܳ��ȳ�512�ֽ�ʱ��ֻ����ǰ512���ֽ�
	unsigned char aa : 1;     //1λ��Ȩ����(Authoritative answer),��ʾ��Ӧ�ķ������Ƿ���Ȩ��DNS��������ֻ����Ӧ��Ϣ����Ч��
	unsigned char opCode : 4; //4λ��0:��׼��ѯ ,ָʾ��������ͣ������������趨����Ӧ��Ϣ�и��ø�ֵ�� 1:�����ѯ , 2:������״̬����
	unsigned char qr : 1;     //1λ��0��ʾ��ѯ�����ģ�1��ʾ��Ӧ����
	
	unsigned char rCode : 4;  //4λ����Ӧ��(Response coded)����������Ӧ����
	unsigned char z : 3;      //3λ������Ϊ0�������ֶ�
	unsigned char ra : 1;     //1λ���ݹ����(Recursion Available),��ֵ����Ӧ��Ϣ�б����û�������Ա����������Ƿ�֧�ֵݹ��ѯ��

	UINT16 qdCount;   //question section�����������16λ
	UINT16 anCount;   //answer section��RR(Resource Record)������16λ
	UINT16 nsCount;   //authority records section��RR������16λ
	UINT16 arCount;   //additional records section��RR������16λ
}DNSHeader;
#pragma pack(pop)  //�ָ�ԭ���Ķ��뷽ʽ


//Question���ֵ�ÿһ��ʵ��ĸ�ʽ
typedef struct
{
	char* qName;	//�ֽ�����������0x00��Ϊ����������ʾ��ѯ������������������"."�ŷָ���˶�α�ǩ����QNAME�У�ÿ�α�ǩǰ���һ�����֣���ʾ��������ǩ�ĳ��ȡ�
	UINT16 qType;	//ռ2���ֽڡ���ʾRR����
	UINT16 qClass;	//ռ2���ֽڡ���ʾRR����
}QUESTION;


//Answer��Authority��Additional���ָ�ʽһ�£�ÿ���ֶ�������ʵ����ɣ�ÿ��ʵ�弴Ϊһ��RR
typedef struct
{
	char* name;
	UINT16 type;	//ռ2���ֽڡ���ʾRR�����ͣ���A��CNAME��NS��
	UINT16 rclass;	//ռ2���ֽڡ���ʾRR�ķ���
	UINT32 ttl;		//ռ4���ֽڡ���ʾRR�������ڣ���RR����ʱ������λ����
	UINT16 rdLength;//ռ2���ֽڡ�ָ��RDATA�ֶε��ֽ���
	char* rData;
}RR;

//DNS����ͷ�������⣬��Ӧ
typedef struct DnsPacket
{
	DNSHeader* header;

	QUESTION* queries;//��ѯ�������򣬶�̬��������������qdCount����
	RR* answers;	//�ش��������򣬶�̬��������������anCount����
	RR* authority;	//Ȩ�����Ʒ��������򣬶�̬��������������nsCount����
	RR* additional;	//������Ϣ����,��̬��������������arCount����

}DNSPacket;

//DNS���󣨴����������
typedef struct DnsRequest
{
	BOOL isServed;
	int seq;//��ţ���ӡʱ���
	SYSTEMTIME systemTime;//ϵͳʱ��,��ӡ������Ϣʱ���
	int ttl;
	int oldID;
	int newID;
	DNSPacket* packet;
	SOCKADDR_IN clientAddr;
	int clientAddrLen;
}DNSRequest;

//DNS����أ��������
typedef struct RequestPool//����ؽڵ㣬ִ�����ɾ���ڵ�
{
	BOOL isAvailable;//��ʼΪTRUE�����߳̿�ʼ����ʱ��ΪFALSE
	DNSRequest* requestPtr;
	struct RequestPool* nextRequestPtr;
}REQUESTPool;
typedef REQUESTPool* REQUESTPoolPtr;

//�����洢��Դ
typedef struct Host
{
	int type;//��Դ���� ADDR_NORMAL / ADDR_ERROR
	uint32_t ipAddress;//IP��ַ
	char* domainName;//����
	struct Host* nextHostPtr;
}HOST;
typedef HOST* HOST_PTR;

//���ϲ�DNS��ȡ����Դ������
typedef struct Cached
{
	int ttl;
	uint32_t ipAddress;//IP��ַ
	char* domainName;//����
	char* cName;//����
	struct Cached* nextCachedPtr;
}CACHED;
typedef CACHED* CACHED_PTR;


extern HOST_PTR hostTableFront[36]; //�ֱ����a-z��0-9��ͷ������
extern HOST_PTR hostTableRear[36]; //��ͷa-z��0-9������Դβָ��
extern CACHED_PTR cachedTableFront[36]; //�ֱ����a-z��0-9��ͷ������
extern CACHED_PTR cachedTableRear[36]; //��ͷa-z��0-9������Դβָ��
extern int hostCount[36];//������Դÿ�����ֵ���Դ��
extern int cachedCount[36];//������Դÿ�����ֵ���Դ��
extern BOOL isCachedOperateAvailable;//ͬʱֻ����һ���̶߳�cached��Դ���и�д���൱��mutex
extern REQUESTPool* requestPool;//�����ͷ��
extern int requestCount;//�����������Ŀ
extern BOOL isPoolOperateAvailable;//ͬʱֻ����һ���̶߳��������Դ���и�д���൱��mutex
extern SOCKET serverSocket;//��������ͻ���ͨ���׽���
extern int newIdDistribute;//�·���id������MAX_REQUEST���������

void InitHostTable();//��ʼ����Դ�б�
void InitCachedTable();//��ʼ��������Դ�б�
void InputHostFile();//������Դ
void AddHostToTable(HOST_PTR currentHost, char initial);//����Դ��ӵ��б���
int InitDNSServer();//����WSA�����׽��ֿ�,���������׽��ֲ��󶨶˿�

DNSHeader* GetHeaderStruct(char* headerStartLoc, char** nextStartLoc);	//dnsͷ�ַ�ת��Ϊdnsͷ�ṹ��
void MakeQueryStruct(QUESTION* packetQuery, char* queryStartLoc, char** nextStartLoc);	//dns������ַ�ת��Ϊdns����νṹ��
void MakeRRStruct(RR* packetResponse, char* responseStartLoc, char* headerStartLoc, char** nextStartLoc);	//dns��Ӧ���ַ�ת��Ϊdns��Ӧ�νṹ��
char* GetHeaderString(DNSHeader* header);		//dnsͷ�ṹ��ת��Ϊdnsͷ�ַ�
char* GetQueryString(QUESTION* query);			//dns����νṹ��ת��Ϊdns������ַ�
char* GetRRString(RR* response);				//dns��Ӧ�νṹ��ת��Ϊdns��Ӧ���ַ�
DNSPacket* MakeDNSPacket(char* recvString);		//��dns�ַ������dns���ṹ�����Է���
char* GetDNSPacketString(DNSPacket* packet, int* len);	//��dns���ṹ�����ַ������Է���

void HandleRequestThread(void* lpvoid);	//����dns�յ�������
void HandleReplyThread(void* lpvoid);	//�����ϲ�dns�Ļ�Ӧ
int AddDNSRequestToPool(DNSRequest*);	//�����յ��Ŀͻ���������뵽��������棬���ص�ǰ������Ŀ������-1������������ʧ��
DNSRequest* GetDNSRequest();			//������������ȡ����ִ�е�����
DNSRequest* FinishDNSRequestInPool(int);//��������б�����������
void HandleReplyPacket(char*);		//�����ϲ�dns��Ӧ�����cache�ĵ�ַ
int getAddrStatus(char* addr, UINT32 ipAddr[30], int* count);//��ȡ�˵�ַ��״̬��blocked cashed notfound
int getCNameStatus(char* name, char** domainName);
DNSPacket* formDNSPacket(DNSPacket* clientPacket, UINT32 ipAddr[30], int addrStatus, int count);//���ݵ�ַblocked��cached���������DNS���ṹ��Ĵ���
DNSPacket* FormCNAMEPacket(DNSPacket* clientPacket, char* domainName);
void FlushDnsCacheTTLThread();		//��������cache��ַ��ʣ����Чʱ��
void FlushDNSRequestTTLThread();	//����������������������ʣ����Чʱ��
int GetTableSeq(char initial);		//���������±�

void PrintDebugInfo(DNSRequest* req);
void PrintRecvPacketInfo(char* recv, int len, DNSHeader* header);
char* GetNormalDomainName(char* DNSDomainName);//��dns��ʽ������ת���ɳ�����ʽ������
char* GetDNSDomainName(char* normalDomainName);//�ѳ�����ʽ������ת����dns��ʽ������

void FreePacketSpace(DNSPacket* packet);//�ͷ�dns���ķ���ռ䣬��������ʱpacketָ��NULL

#endif // !DNS_HEADER