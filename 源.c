#include"DNSHeader.h"

HOST_PTR hostTableFront[36]; //分别代表a-z、0-9开头的域名
HOST_PTR hostTableRear[36]; //开头a-z、0-9域名资源尾指针
CACHED_PTR cachedTableFront[36]; //分别代表a-z、0-9开头的域名
CACHED_PTR cachedTableRear[36]; //开头a-z、0-9域名资源尾指针
int hostCount[36];//本机资源每个部分的资源数
int cachedCount[36];//缓存资源每个部分的资源数
BOOL isCachedOperateAvailable;//同时只能有一个线程对cached资源进行改写，相当于mutex
REQUESTPool* requestPool;//请求池
int requestCount;//请求池请求数目
BOOL isPoolOperateAvailable;//同时只能有一个线程对请求池资源进行改写，相当于mutex
SOCKET serverSocket;//服务器与客户端通信套接字
int newIdDistribute = 0;//新分配id，除余MAX_REQUEST最大请求数，可避免回环
int debugLevel = 0;//调试等级，1为简单输出，2为输出冗长的调试信息

int clientReqCount = 0;

int main(int argc, char** argv)
{
	//debugLevel = argc;
	//确定调试信息级别
	if (strcmp(argv[1], "-d") == 0)//调试信息级别1（仅输出时间坐标，序号，客户端IP地址， 查询的域名）
	{
		debugLevel = 1;
	}
	else if (strcmp(argv[1], "-dd") == 0)//调试信息级别2 （输出冗长的调试信息）
	{
		debugLevel = 2;
	}
	else
	{
		debugLevel = 0; //无调试信息输出
	}
	printf("当前调试信息等级为：%d\n", debugLevel);

	int err = 0, erro = 0;//函数返回信息

	//初始化本机资源列表
	InitHostTable();
	InitCachedTable();
	InputHostFile();
	isPoolOperateAvailable = TRUE;
	isCachedOperateAvailable = TRUE;
	//创建服务器监听socket
	err = InitDNSServer(&serverSocket);
	if (err == 1)
	{
		printf("Failed to initialize DNSserver.\n");
		return 0;
	}

	requestPool = (REQUESTPool*)malloc(sizeof(REQUESTPool));//请求池头部初始化分配空间
	if (requestPool == NULL)
	{
		printf("Failed to malloc requestPool.\n");
		return 0;
	}
	requestPool->isAvailable = FALSE;//头部指向第一个请求，本身不是请求
	requestPool->requestPtr = NULL;//本身无请求内容
	requestPool->nextRequestPtr = NULL;//指向第一个指针暂为空

	//四个处理接收到请求的线程,不是同时只能收到四个请求，同时处理四个，接收到的请求存放在请求池pool里
	int first = 1, second = 2, third = 3, fourth = 4;
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &first);
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &second);
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &third);
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &fourth);

	//两个缩短请求池和资源寿命的进程
	_beginthread((void(__cdecl*) (void*))FlushDnsCacheTTLThread, 0, NULL);
	_beginthread((void(__cdecl*) (void*))FlushDNSRequestTTLThread, 0, NULL);

	printf("Initialize Complete.\n\n");

	//接受客户端发来的请求
	while (TRUE)
	{
		char recvbuf[BUF_SIZE];
		/*char recvbuf[BUF_SIZE] = { 0x00, 0x02, 0x01, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
			0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03,
			0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};*/
			//接受缓存
		int recvbuflen = BUF_SIZE, sendbuflen = BUF_SIZE;//缓存空间大小
		struct sockaddr_in clientAddr;//用户地址
		int clientAddrLen = sizeof(clientAddr);//用户地址长度

		memset(recvbuf, '\0', sizeof(recvbuf));//接受缓存清零
		ZeroMemory(&clientAddr, sizeof(clientAddr));//客户地址清零

		//控制套接字避免错误
		DWORD lenReturned = 0;//实际返回字节数
		BOOL banNewBehav = FALSE;//传入信息
		DWORD status;
		status = WSAIoctl(serverSocket, _WSAIOW(IOC_VENDOR, 12),
			&banNewBehav, sizeof(banNewBehav),
			NULL, 0, &lenReturned,
			NULL, NULL);

		if (status == SOCKET_ERROR)
		{
			return 0;
		}

		//接收请求，放入请求池
		err = recvfrom(serverSocket, recvbuf, recvbuflen, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
		int len = err;//接收的长度
		if (err == SOCKET_ERROR) //接收异常
		{

			erro = WSAGetLastError();//获取异常类型
			if (erro == WSAEWOULDBLOCK)//暂无数据可读
			{
				Sleep(20);
				continue;
			}
			else//读取数据失败
			{
				printf("Failed to receive from client.\n");
				break;
			}
		}
		else//构建请求放入请求池供处理线程处理
		{
			//printf("Bytes received from client: %d\n", err);
			//创建请求
			DNSRequest* newRequest;
			newRequest = (DNSRequest*)malloc(sizeof(DNSRequest));
			if (newRequest == NULL)
			{
				printf("Failed to malloc newRequest.\n");
				return;
			}
			//构造请求
			newRequest->seq = clientReqCount++;
			GetLocalTime(&newRequest->systemTime);//请求时间
			newRequest->clientAddr = clientAddr;
			newRequest->clientAddrLen = clientAddrLen;
			newRequest->isServed = FALSE;
			newRequest->ttl = REQUEST_TTL;
			newRequest->packet = MakeDNSPacket(recvbuf);

			err = AddDNSRequestToPool(newRequest);	//将新收到的客户端请求加入到请求池里面
			if (err == -1)//请求池无法再加入请求了
				printf("Too many requests or malloc error. Current request failed to accept.\n");
			else
				;// printf("Request accepted successfully.\n");

			PrintDebugInfo(newRequest);
			if (debugLevel == 2)//输出冗长调试信息
			{
				char clientIP[16];
				inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, 16);

				printf("接收到客户端（IP:%s，端口:%d）的请求包，共%d字节，请求包的数据如下：\n",
					clientIP, ntohs(clientAddr.sin_port), len);

				newRequest->packet->header->id = ntohs(*(UINT16*)recvbuf);
				PrintRecvPacketInfo(recvbuf, len, newRequest->packet->header);
			}
		}
	}
	//关闭套接字
	closesocket(serverSocket);

	//关闭winsocket库
	WSACleanup();
}

void HandleRequestThread(void* lpvoid)
{
	int id = *(int*)lpvoid;//线程编号
	char* upperDNSAddr = UPPER_DNS;//上层DNS IP地址
	printf("%d 号处理请求线程创建成功.\n", id);
	char* sendBuf;//发送缓存
	int sendBufLen = BUF_SIZE;//发送缓存大小
	int err = 0;//函数返回信息

	sendBuf = (char*)malloc(sendBufLen * sizeof(char));//为发送缓存分配空间
	if (sendBuf == NULL)
	{
		printf("Failed to malloc sendbuf.\n");
		return;
	}

	//创建上层DNS地址用以进行通信
	struct sockaddr_in servAddr;//上层dns地址
	ZeroMemory(&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(PORT);
	//将ipv4或ipv6地址在点分十进制和二进制整数之间转换
	inet_pton(AF_INET, upperDNSAddr, &servAddr.sin_addr);

	//创建本机地址用以向上层DNS发送信息
	struct sockaddr_in myAddr;
	ZeroMemory(&myAddr, sizeof(myAddr));
	myAddr.sin_family = AF_INET;
	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);//32位长整型主机顺序转换为网络字节顺序
	myAddr.sin_port = htons(UPPERPORT(id));//32位短整型

	SOCKET upperDNSSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//创建与上层dns进行通信的socket
	bind(upperDNSSocket, (struct sockaddr*)&myAddr, sizeof(myAddr));//绑定socket地址端口

	//控制套接字避免错误
	DWORD lenReturned = 0;//实际返回字节数
	BOOL banNewBehav = FALSE;//传入信息
	WSAIoctl(upperDNSSocket, _WSAIOW(IOC_VENDOR, 12), &banNewBehav, sizeof(banNewBehav),
		NULL, 0, &lenReturned, NULL, NULL);

	_beginthread((void(__cdecl*) (void*))HandleReplyThread, 0, &upperDNSSocket);//等待从上层dns的回应

	//处理请求
	while (TRUE)
	{
		//从请求池中取出可以处理的请求
		DNSRequest* request = NULL;
		while (request == NULL)
		{
			Sleep(20);
			request = GetDNSRequest();
		}

		DNSPacket* recvPacket = request->packet;

		//UINT32 ipAddress = 0;
		char* domainName = NULL;

		UINT32 ipAddress[30];//找到的ip地址
		int count = 0;//在本地（初始+缓存）找到的地址数

		//地址类型ADDR_ERROR/ADDR_NORMAL/ADDR_NOT_FOUND
		char* qName = GetNormalDomainName(recvPacket->queries[0].qName);
		int addrStatus = ADDR_NOT_FOUND;
		if (recvPacket->queries[0].qType == CNAME)
		{
			addrStatus = getCNameStatus(qName, &domainName);
		}
		else if (recvPacket->queries[0].qType == A)
		{
			addrStatus = getAddrStatus(qName, ipAddress, &count);
		}

		//根据问询地址状态进行处理
		switch (addrStatus)
		{
		case ADDR_ERROR:
		case ADDR_NORMAL:
		{
			//查询到的状态添加到dns包里面
			DNSPacket* resultPacket = NULL;
			if (recvPacket == NULL)
			{
				continue;
			}
			else if (recvPacket->queries[0].qType == CNAME)
			{
				resultPacket = FormCNAMEPacket(recvPacket, domainName);
			}
			else
			{
				resultPacket = formDNSPacket(recvPacket, ipAddress, addrStatus, count);
			}

			if (resultPacket == NULL)
			{
				printf("%d号线程构建响应DNS包失败.\n", id);
				return;
			}
			resultPacket->header->id = request->oldID;

			//将DNS包结构体转换为字符串形式存入发送缓存
			sendBuf = GetDNSPacketString(resultPacket, &sendBufLen);

			//发送回应至客户端
			err = sendto(serverSocket, sendBuf, sendBufLen, 0, (struct sockaddr*)&(request->clientAddr), request->clientAddrLen);//发送回应到客户端
			int len = err;
			if (err == SOCKET_ERROR)
				printf("%d号线程向客户端发送响应包失败.\n", id);
			else
			{
				//打印调试信息
				if (debugLevel == 2)
				{
					char clientIP[16];
					inet_ntop(AF_INET, &request->clientAddr.sin_addr, clientIP, 16);

					printf("%d号线程向客户端（IP:%s，端口:%d）发送响应包，共%d字节，ID：[%d->%d]\n",
						id, clientIP, ntohs(request->clientAddr.sin_port),
						len, request->newID, request->oldID);
				}
			}

			DNSRequest* remove = FinishDNSRequestInPool(request->newID);//从请求池中移除请求
		}
		break;
		case ADDR_NOT_FOUND:
		{
			int len;//发送包大小
			recvPacket->header->id = request->newID;
			sendBuf = GetDNSPacketString(recvPacket, &len);//将DNS包结构体转换为字符串形式存入发送缓存

			//发送查询请求到上层dns
			err = sendto(upperDNSSocket, sendBuf, len, 0, (struct sockaddr*)&servAddr, sizeof(servAddr));
			len = err;

			//打印调试信息
			if (debugLevel == 2)
			{
				printf("\n%d号线程向上层DNS服务器（IP:%s，端口:%d）发送请求包，共%d字节，ID：[%d->%d]\n",
					id, upperDNSAddr, ntohs(servAddr.sin_port),
					len, request->oldID, request->newID);
			}

			//超时请求没有结束，重发upper dns请求
			Sleep(UPPER_TIMEOUT);
			if (FinishDNSRequestInPool(request->newID) != NULL)
			{
				err = sendto(upperDNSSocket, sendBuf, len, 0, (struct sockaddr*)&servAddr, sizeof(servAddr));

				//打印调试信息
				if (debugLevel == 2)
				{
					printf("\n向上层DNS服务器发送的请求超时，进行重发：\n");
					printf("%d号线程向上层DNS服务器（IP:%s，端口:%d）发送请求包，共%d字节，ID：[%d->%d]\n",
						id, upperDNSAddr, ntohs(servAddr.sin_port),
						len, request->oldID, request->newID);
				}
			}

			if (err == SOCKET_ERROR)
				printf("%d号线程向上层DNS服务器发送请求包失败.\n", id);
			else
				;// printf("send query to upper DNS [%d].\n", id);
		}
		break;
		}
	}
}

void HandleReplyThread(void* lpvoid)
{
	int err = 0, erro = 0;
	SOCKET* upperDNSSocket = (SOCKET*)lpvoid;
	struct sockaddr_in servaddr;
	int dnsbuflen = BUF_SIZE, servaddrlen = sizeof(servaddr);
	char dnsbuf[BUF_SIZE];

	while (1)
	{
		//上层DNS接收信息
		err = recvfrom(*upperDNSSocket, dnsbuf, dnsbuflen, 0, (struct sockaddr*)&servaddr, &servaddrlen);
		int len = err;
		if (err == SOCKET_ERROR)//接收异常
		{
			erro = WSAGetLastError();//获取异常类型
			if (erro == WSAEWOULDBLOCK)//暂无数据可读
			{
				Sleep(20);
				continue;
			}
			else//读取数据失败
			{
				if (debugLevel == 2)
				{
					printf("从上层DNS服务器接收响应失败.\n");
				}
				break;
			}
		}
		else//接收信息成功
		{
			//printf("Bytes %d received from upper DNS.\n", err);
			if (debugLevel == 2)//输出冗长调试信息
			{
				printf("接收到上层DNS服务器（IP:%s，端口:%d）的响应包，共%d字节，响应包的数据如下：\n",
					UPPER_DNS, ntohs(servaddr.sin_port), len);

				char* nextLoc = NULL;
				DNSHeader* header = GetHeaderStruct(dnsbuf, &nextLoc);
				PrintRecvPacketInfo(dnsbuf, len, header);
			}

			int newID = ntohs(*(u_short*)dnsbuf);//提取出前u_short长度的id并由网络顺序改为主机顺序
			DNSRequest* req = FinishDNSRequestInPool(newID);//在请求池里标识为已完成

			if (req == NULL)
				printf("failed to remove request in pool.\n");
			else
			{
				//printf("remove request in pool.\n");
				*(u_short*)dnsbuf = htons(req->oldID);//主机顺序改为网络顺序,将包编号的改为旧编号
				err = sendto(serverSocket, dnsbuf, dnsbuflen, 0, (struct sockaddr*)&(req->clientAddr), req->clientAddrLen);//上层dns回应发送到客户端
				len = err;
				if (err == SOCKET_ERROR)
				{
					printf("failed to send reply to client.\n");
					erro = WSAGetLastError();
					printf("error %d.\n", erro);
				}
				else
				{
					//打印调试信息
					if (debugLevel == 2)
					{
						char clientIP[16];
						inet_ntop(AF_INET, &req->clientAddr.sin_addr, clientIP, 16);

						printf("\n向客户端（IP:%s，端口:%d）发送响应包，共%d字节，ID：[%d->%d]\n",
							clientIP, ntohs(req->clientAddr.sin_port),
							len, req->newID, req->oldID);
					}
				}
			}
			HandleReplyPacket(dnsbuf);//处理上层DNS回应，添加资源到缓存列表
		}
	}
}

int AddDNSRequestToPool(DNSRequest* request)	//将新收到的客户端请求加入到请求池里面，返回当前请求数目
{
	int i = 0;
	REQUESTPool* newPtr;
	while (!isPoolOperateAvailable)//可以上锁时进行请求提取
	{
		Sleep(100);
	}
	isPoolOperateAvailable = FALSE;//上锁

	//从请求池头部指向的第一个请求开始链表遍历寻找到最后一个结点
	for (REQUESTPool* ptr = requestPool; i <= MAX_REQUEST && ptr != NULL; ptr = ptr->nextRequestPtr)
	{
		i++;
		if (ptr->nextRequestPtr == NULL)
		{
			newPtr = (REQUESTPool*)malloc(sizeof(REQUESTPool));//添加请求池结点
			if (newPtr == NULL)
			{
				printf("给新请求分配空间失败...\n");
				return -1;
			}
			else
				;

			requestCount++;//当前请求池里的请求数目更新
			ptr->nextRequestPtr = newPtr;//连接新请求到链表中
			newPtr->isAvailable = TRUE;//可用请求
			newPtr->requestPtr = request;//添加请求
			newPtr->requestPtr->oldID = request->packet->header->id;//请求的原ID（即客户端发送的dns请求包的ID）
			newPtr->requestPtr->newID = newIdDistribute;
			newIdDistribute++;
			newIdDistribute = newIdDistribute % MAX_REQUEST;//新分配ID增长

			newPtr->nextRequestPtr = NULL;//尾
			isPoolOperateAvailable = TRUE;//处理完解锁

			return i;//返回加入新请求之后的请求总数
		}
		else
			;
	}
	return -1;//请求池已满，添加请求失败
}


DNSRequest* GetDNSRequest()			//从请求池里面获取可以执行的请求
{
	DNSRequest* retPtr = NULL;
	while (!isPoolOperateAvailable)//可以上锁时进行请求提取
	{
		Sleep(100);
	}
	isPoolOperateAvailable = FALSE;//上锁

	//从请求池头部指向的第一个请求开始链表遍历寻找第一个可执行的请求
	for (REQUESTPool* ptr = requestPool->nextRequestPtr; ptr != NULL; ptr = ptr->nextRequestPtr)
	{
		//找到可以执行的请求返回
		if (ptr->isAvailable)
		{
			ptr->isAvailable = FALSE;//已有线程开始处理请求，故当前此请求不可用
			retPtr = ptr->requestPtr;
		}
	}
	isPoolOperateAvailable = TRUE;//处理完解锁
	return retPtr;//若没有找到可以执行的返回空指针
}

DNSRequest* FinishDNSRequestInPool(int newID)
{
	DNSRequest* retPtr = NULL;
	while (!isPoolOperateAvailable)//可以上锁时进行请求提取
	{
		Sleep(100);
	}
	isPoolOperateAvailable = FALSE;//上锁

	//从请求池头部开始，链表遍历寻找制定ID请求
	for (REQUESTPool* ptr = requestPool; ptr->nextRequestPtr != NULL; ptr = ptr->nextRequestPtr)
	{
		//找到目标请求的前驱请求，删除目标请求，修改链表
		if (ptr->nextRequestPtr->requestPtr->newID == newID)
		{
			retPtr = ptr->nextRequestPtr->requestPtr;
			ptr->nextRequestPtr = ptr->nextRequestPtr->nextRequestPtr;
			requestCount--;
			break;
		}
	}
	isPoolOperateAvailable = TRUE;//处理完解锁
	return retPtr;//若没有找到目标请求返回空指针
}

void HandleReplyPacket(char* packet)//分析上层dns回应，添加cache的地址
{
	//dns回应转换为dns结构体处理
	DNSPacket* repPacket = MakeDNSPacket(packet);
	BOOL isCnameSingal = TRUE;
	char* cname = NULL;
	for (int i = 0; i < repPacket->header->anCount; i++)
	{
		if (repPacket->answers == NULL)
			continue;
		if (repPacket->answers[i].type != A && repPacket->answers[i].type != CNAME)//不是A类型且不是CNAME类型
			continue;

		if (repPacket->answers[i].type == CNAME)//保存CNAME
		{
			cname = GetNormalDomainName(repPacket->answers[i].name);
		}
		else
		{

			//将上层dns的回应地址添加到cache之中
			CACHED_PTR newCached;
			newCached = (CACHED_PTR)malloc(sizeof(CACHED));
			if (newCached == NULL)
			{
				printf("Failed to malloc newCached.\n");
				return;
			}
			char* answersDomainName = GetNormalDomainName(repPacket->answers[i].name);
			char initial = answersDomainName[0];
			int tableSeq = GetTableSeq(initial);//寻找cache存放列表结点

			if (cachedCount[i] == MAX_CACHED)//缓存到达上限，无法进行添加
			{
				printf("Too many cached resources, cuurent resource fialed to be cached.\n");
				return;
			}

			//添加缓存资源列表结点
			while (!isCachedOperateAvailable)//可以上锁时进行缓存操作
			{
				Sleep(100);
			}
			isCachedOperateAvailable = FALSE;//上锁
			if (cachedTableFront[tableSeq] == NULL)//如果队头还是NULL，则代表队列是空的
			{
				cachedTableFront[tableSeq] = newCached;
				cachedTableRear[tableSeq] = newCached;
			}
			else//队列非空
			{
				cachedTableRear[tableSeq]->nextCachedPtr = newCached;
				cachedTableRear[tableSeq] = newCached;
			}
			cachedCount[tableSeq]++;

			//填入资源信息
			int len = strlen(answersDomainName);
			newCached->domainName = (char*)malloc(sizeof(char) * (len + 1));//给域名分配空间
			if (newCached->domainName == NULL)
			{
				printf("Failed to malloc newCached->domainName.\n");
				return;
			}
			strcpy(newCached->domainName, answersDomainName);//缓存域名

			newCached->cName = cname;//缓存别名
			newCached->ttl = CACHED_TTL;//设置ttl
			newCached->nextCachedPtr = NULL;
			//inet_pton(AF_INET, repPacket->answers[i].rData, (PVOID)&newCached->ipAddress);//缓存IP
			newCached->ipAddress = ntohl(*((UINT32*)repPacket->answers[i].rData));

			isCachedOperateAvailable = TRUE;//解锁

			printf("缓存新域名数据到本地： %s (CNAME：%s)\n", newCached->domainName, newCached->cName);
		}

	}
}

int getAddrStatus(char* addr, UINT32 ipAddr[30], int* count)//获取此地址的状态：error/cached/ notfound
{
	unsigned int i;
	int ipCount = 0;
	int status = ADDR_NOT_FOUND;
	int tableSeq = GetTableSeq(addr[0]);//域名首字符对应的表的下标

	//初始化
	for (i = 0; i < 30; i++)
	{
		ipAddr[i] = 0x0;
	}

	//将无法识别“.”转化为字符“.”
	for (i = 0; i < strlen(addr); i++)
	{
		if (addr[i] < 0x20)
			addr[i] = '.';
	}

	//在本机资源列表中查找
	for (HOST_PTR ptr = hostTableFront[tableSeq]; ptr != NULL; ptr = ptr->nextHostPtr)
	{
		if (strcmp(ptr->domainName, addr) == 0)
		{
			ipAddr[ipCount] = ptr->ipAddress;//保存IP
			ipCount++;//计数器加一

			if (*ipAddr != 0)
			{
				status = ADDR_NORMAL;
			}
			else
			{
				return ADDR_ERROR;

			}
		}
		else
			;
	}

	//在缓存资源列表中查找
	while (!isCachedOperateAvailable)//可以上锁时进行缓存操作
	{
		Sleep(100);
	}
	isCachedOperateAvailable = FALSE;//上锁
	for (CACHED_PTR ptr = cachedTableFront[tableSeq]; ptr != NULL; ptr = ptr->nextCachedPtr)
	{
		if (ptr->cName != NULL)
		{
			if ((strcmp(ptr->domainName, addr) == 0) || (strcmp(ptr->cName, addr) == 0))//找到匹配
			{
				ipAddr[ipCount] = ptr->ipAddress;//保存IP
				ipCount++;//计数器加一

				ptr->ttl = CACHED_TTL;//刷新ttl

				isCachedOperateAvailable = TRUE;//解锁
				status = ADDR_NORMAL;
			}
			else
				;
		}
		else
		{
			if (strcmp(ptr->domainName, addr) == 0)//找到匹配
			{
				ipAddr[ipCount] = ptr->ipAddress;//保存IP
				ipCount++;//计数器加一

				ptr->ttl = CACHED_TTL;//刷新ttl

				isCachedOperateAvailable = TRUE;//解锁
				status = ADDR_NORMAL;
			}
			else
				;
		}
	}
	isCachedOperateAvailable = TRUE;//解锁

	*count = ipCount;
	return status;
}

int getCNameStatus(char* name, char** domainName)
{
	int tableSeq = GetTableSeq(name[0]);
	/*
	//在缓存资源列表中查找
	while (!isCachedOperateAvailable)//可以上锁时进行缓存操作
	{
		Sleep(100);
	}
	isCachedOperateAvailable = FALSE;//上锁
	for (CACHED_PTR ptr = cachedTableFront[tableSeq]; ptr != NULL; ptr = ptr->nextCachedPtr)
	{
		if (strcmp(ptr->cName, name) == 0)//找到匹配
		{
			*domainName = (char*)malloc(sizeof(char) * (strlen(ptr->domainName + 1)));
			strcpy(*domainName, ptr->domainName);
			ptr->ttl = CACHED_TTL;//刷新ttl

			isCachedOperateAvailable = TRUE;//解锁
			return ADDR_NORMAL;
		}
	}
	isCachedOperateAvailable = TRUE;//解锁
	*/
	return ADDR_NOT_FOUND;
}

//构造响应包
DNSPacket* formDNSPacket(DNSPacket* clientPacket, UINT32 ipAddr[30], int addrStatus, int count)//根据地址blocked或cached的情况进行DNS包结构体的创建
{
	//准备工作
	DNSPacket* retPacket = (DNSPacket*)malloc(sizeof(DNSPacket));
	if (retPacket == NULL)
	{
		//printf("Failed to malloc retPacket.\n");
		return NULL;
	}
	DNSHeader* retHeader = (DNSHeader*)malloc(sizeof(DNSHeader));
	if (retHeader == NULL)
	{
		//printf("Failed to malloc retHeader.\n");
		return NULL;
	}
	QUESTION* retQuestion = clientPacket->queries;
	RR* retResponse = (RR*)malloc(sizeof(RR) * count);
	if (retResponse == NULL)
	{
		//printf("Failed to malloc retResponse.\n");
		return NULL;
	}

	memset(retHeader, 0, sizeof(DNSHeader));

	//根据地址类型进行DNS响应包构造
	if (addrStatus == ADDR_ERROR)//屏蔽地址
	{
		retHeader->id = clientPacket->header->id;//响应包的id与请求包相同
		retHeader->qr = 1;//1表示响应
		retHeader->opCode = clientPacket->header->opCode;//响应包的opcode与请求包的相同
		retHeader->aa = 0;
		retHeader->tc = 0;
		retHeader->rd = 1;
		retHeader->ra = 1;
		retHeader->rCode = 3;//Name Error，the domain name referenced in the query does not exist
		retHeader->qdCount = 0;
		retHeader->anCount = 0;
		retHeader->nsCount = 0;
		retHeader->arCount = 0;

		//DNS包结构体
		retPacket->header = retHeader;
		retPacket->queries = NULL;
		retPacket->answers = NULL;
		retPacket->authority = NULL;
		retPacket->additional = NULL;
	}
	else//正常地址
	{
		int i = 0;
		for (i = 0; i < count; i++)
		{
			//构造DNS响应结构体
			retResponse[i].name = clientPacket->queries->qName;
			retResponse[i].type = A;
			retResponse[i].rclass = clientPacket->queries->qClass;
			retResponse[i].ttl = 0x100;
			retResponse[i].rdLength = 4;
			retResponse[i].rData = (char*)malloc(sizeof(char) * (retResponse[i].rdLength + 1));
			if (retResponse[i].rData == NULL)
			{
				//printf("Failed to malloc retResponse->rData.\n");
				return NULL;
			}
			*(UINT32*)(retResponse[i].rData) = htonl(ipAddr[i]);

			//头部
			retHeader->id = clientPacket->header->id;
			retHeader->qr = 1;
			retHeader->opCode = clientPacket->header->opCode;
			retHeader->aa = 0;
			retHeader->tc = 0;
			retHeader->rd = 1;
			retHeader->ra = 1;
			retHeader->rCode = 0;
			retHeader->qdCount = 1;
			retHeader->anCount = count;
			retHeader->nsCount = 0;
			retHeader->arCount = 0;

			//DNS包结构体
			retPacket->header = retHeader;
			retPacket->queries = retQuestion;
			retPacket->answers = retResponse;
			retPacket->authority = NULL;
			retPacket->additional = NULL;
		}

	}
	return retPacket;
}
//构造针对cname的响应包
DNSPacket* FormCNAMEPacket(DNSPacket* clientPacket, char* domainName)
{
	//准备工作
	DNSPacket* retPacket = (DNSPacket*)malloc(sizeof(DNSPacket));
	if (retPacket == NULL)
	{
		return NULL;
	}
	DNSHeader* retHeader = (DNSHeader*)malloc(sizeof(DNSHeader));
	if (retHeader == NULL)
	{
		return NULL;
	}
	QUESTION* retQuestion = clientPacket->queries;
	RR* retResponse = (RR*)malloc(sizeof(RR));
	if (retResponse == NULL)
	{
		return NULL;
	}

	//构造DNS响应结构体
	retResponse->name = clientPacket->queries->qName;
	retResponse->type = CNAME;
	retResponse->rclass = clientPacket->queries->qClass;
	retResponse->ttl = 0x100;
	retResponse->rdLength = (UINT16)(strlen(domainName) + 1);
	retResponse->rData = GetDNSDomainName(domainName);

	//头部
	retHeader->id = clientPacket->header->id;
	retHeader->qr = 1;
	retHeader->opCode = clientPacket->header->opCode;
	retHeader->aa = 0;
	retHeader->tc = 0;
	retHeader->rd = 1;
	retHeader->ra = 1;
	retHeader->rCode = 0;
	retHeader->qdCount = 1;
	retHeader->anCount = 1;
	retHeader->nsCount = 0;
	retHeader->arCount = 0;

	//DNS包结构体
	retPacket->header = retHeader;
	retPacket->queries = retQuestion;
	retPacket->answers = retResponse;
	retPacket->authority = NULL;
	retPacket->additional = NULL;

	return retPacket;
}

void FlushDnsCacheTTLThread()		//定期缩短cache地址的剩余有效时间
{

	while (1)
	{
		Sleep(10000);
		while (!isCachedOperateAvailable)//可以上锁时进行缓存操作
		{
			Sleep(100);
		}
		isCachedOperateAvailable = FALSE;//上锁
		for (int i = 0; i < 36; i++)
		{
			CACHED* prevPtr = NULL;
			prevPtr = (CACHED*)malloc(sizeof(CACHED));
			for (prevPtr->nextCachedPtr = cachedTableFront[i]; prevPtr != NULL && prevPtr->nextCachedPtr != NULL; prevPtr = prevPtr->nextCachedPtr)
			{
				prevPtr->nextCachedPtr->ttl -= 4;
				if (prevPtr->nextCachedPtr->ttl < 0)//ttl小于零，删除缓存结点
				{
					if (prevPtr->nextCachedPtr == cachedTableRear[i])//更新尾结点
					{
						cachedTableRear[i] = prevPtr;
					}
					CACHED* waste = prevPtr->nextCachedPtr;
					prevPtr->nextCachedPtr = waste->nextCachedPtr;
					
					if (waste != NULL)
					{
						if (waste->domainName != NULL)
						{
							free(waste->domainName);
							waste->domainName = NULL;
						}
						else
							;
						free(waste);//释放空间
						waste = NULL;
					}
					
				}
				else
					;
			}
		}
		isCachedOperateAvailable = TRUE;//解锁
	}
}

void FlushDNSRequestTTLThread()	//定期缩短请求池里面请求的剩余有效时间
{
	while (1)
	{
		Sleep(10000);
		while (!isPoolOperateAvailable)//可以上锁时进行缓存操作
		{
			Sleep(100);
		}
		isPoolOperateAvailable = FALSE;//上锁
		for (REQUESTPool* prevPtr = requestPool; prevPtr != NULL && prevPtr->nextRequestPtr != NULL; prevPtr = prevPtr->nextRequestPtr)
		{
			prevPtr->nextRequestPtr->requestPtr->ttl -= 4;
			if (prevPtr->nextRequestPtr->requestPtr->ttl < 0)//ttl小于零，删除请求结点
			{
				REQUESTPool* waste = prevPtr->nextRequestPtr;
				prevPtr->nextRequestPtr = prevPtr->nextRequestPtr->nextRequestPtr;

				//释放空间
				FreePacketSpace(waste->requestPtr->packet);
				
				if (waste != NULL)
				{
					free(waste->requestPtr);
					waste->requestPtr = NULL;
					free(waste);//释放空间
					waste = NULL;
				}
				else
					;
			}
		}
		isPoolOperateAvailable = TRUE;//解锁
	}
}

int GetTableSeq(char initial)//返回数组下标
{
	int tableSeq = 0;
	if (initial >= '0' && initial <= '9')//如果域名的首字母是数字
	{
		tableSeq = initial - '0';
	}
	else if (initial >= 'a' && initial <= 'z')//如果域名的首字母是小写英文
	{
		tableSeq = initial - 'a' + 10;
	}
	else//如果域名的首字母是大写英文
	{
		tableSeq = initial - 'A' + 10;
	}
	return tableSeq;
}

//根据调试信息级别打印对应的调试信息
void PrintDebugInfo(DNSRequest* req)
{
	if (debugLevel == 0)//无调试信息输出直接返回
	{
		return;
	}
	else//有调试信息输出
	{
		//调试信息级别1：仅输出时间坐标，序号，客户端IP地址， 查询的域名
		//打印序号
		if (debugLevel == 2)
		{
			printf("\n");
		}
		printf("\n%3d： ", req->seq);

		//打印时间坐标：年-月-日 时：分：秒 客户端IP:
		printf("%d-%d-%d %d:%d:%d  ",
			req->systemTime.wYear, req->systemTime.wMonth, req->systemTime.wDay,
			req->systemTime.wHour, req->systemTime.wMinute, req->systemTime.wSecond);

		//打印客户端IP地址
		char clientIP[16];
		inet_ntop(AF_INET, &req->clientAddr.sin_addr, clientIP, 16);
		printf("客户端IP：%-16s ", clientIP);

		//打印查询的域名
		printf("查询域名:%s", GetNormalDomainName(req->packet->queries[0].qName));

		///调试信息级别2还会输出type和class
		if (debugLevel == 2)
		{
			printf("  TYPE:%d  CLASS:%d", req->packet->queries[0].qType, req->packet->queries[0].qClass);

		}

		printf("\n");
	}
}

//调试级别2的部分信息（关于数据包）
void PrintRecvPacketInfo(char* recv, int len, DNSHeader* header)
{
	//打印接收到的具体的dns包的数据

	//十六进制数据包内容
	int i = 0;
	for (i = 0; i < len; i++)
	{
		printf("%02x ", (unsigned char)recv[i]);
		if ((i % 16 == 15) || (i == len - 1))
		{
			printf("\n");
		}
		else
			;
	}

	//头部分析内容
	printf("其中，Header部分内容如下：\n");
	printf("ID: %d\n", header->id);
	printf("QR: %d, OPCODE: %d, AA: %d, TC: %d, RD: %d, RA: %d, Z: %d, RCODE: %d\n",
		header->qr, header->opCode, header->aa, header->tc,
		header->rd, header->ra, header->z, header->rCode);
	printf("Questions: %d\n", header->qdCount);
	printf("Answer RRs: %d\n", header->anCount);
	printf("Authority RRs: %d\n", header->nsCount);
	printf("Additional RRs: %d\n", header->arCount);
}

//释放dns包的分配空间，函数结束时packet指向NULL
void FreePacketSpace(DNSPacket* packet)
{
	if (packet == NULL)
		return;

	//释放相关的所有空间，注意包含关系释放顺序
	UINT16 qdCount = packet->header->qdCount;
	UINT16 anCount = packet->header->anCount;
	UINT16 nsCount = packet->header->nsCount;
	UINT16 arCount = packet->header->arCount;
	UINT16 i = 0;

	//先释放请求指针中的包指针指向的资源
	//释放头部
	free(packet->header);
	packet->header = NULL;

	//释放query部分
	for (i = 0; i < qdCount; i++)
	{
		free(packet->queries[i].qName);
		packet->queries[i].qName = NULL;
	}
	free(packet->queries);
	packet->queries = NULL;

	//释放answers部分
	for (i = 0; i < anCount; i++)
	{
		free(packet->answers[i].name);
		free(packet->answers[i].rData);
		packet->answers[i].name = NULL;
		packet->answers[i].rData = NULL;
	}
	free(packet->answers);
	packet->answers = NULL;

	//释放authority部分
	for (i = 0; i < nsCount; i++)
	{
		free(packet->authority[i].name);
		free(packet->authority[i].rData);
		packet->authority[i].name = NULL;
		packet->authority[i].rData = NULL;
	}
	free(packet->authority);
	packet->authority = NULL;

	//释放additional部分
	for (i = 0; i < arCount; i++)
	{
		free(packet->additional[i].name);
		free(packet->additional[i].rData);
		packet->additional[i].name = NULL;
		packet->additional[i].rData = NULL;
	}
	free(packet->additional);
	packet->additional = NULL;

	free(packet);
	packet = NULL;

}