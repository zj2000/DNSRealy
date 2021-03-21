#include"DNSHeader.h"

FILE* hostFile;

void InitHostTable()
{
	int i;
	for (i = 0; i < 36; i++)
	{
		hostTableFront[i] = NULL;
		hostTableRear[i] = NULL; 
		hostCount[i] = 0;
	}
}

void InitCachedTable()
{
	int i;
	for (i = 0; i < 36; i++)
	{
		cachedTableFront[i] = NULL;
		cachedTableRear[i] = NULL;
		cachedCount[i] = 0;
	}
}

void InputHostFile()
{
	hostFile = fopen("./dnsrelay.txt", "r");
	if (hostFile != NULL)//如果打开成功
	{
		char ipAddrString[16], name[256];
		while (fscanf(hostFile, "%s%s", ipAddrString, name) != EOF)//文件还未读取结束
		{
			HOST_PTR currentHost = (HOST_PTR)malloc(sizeof(HOST));
			if (currentHost != NULL)//空间分配成功
			{
				IN_ADDR ipAddr;
				int isValid = inet_pton(AF_INET, ipAddrString, (PVOID)&ipAddr);//把点分十进制字符串转换成二进制整数
				if (isValid == 1)//如果转换成功
				{
					currentHost->ipAddress = ntohl(ipAddr.s_addr); 

					if (currentHost->ipAddress == 0)
					{
						currentHost->type = ADDR_ERROR;
					}
					else
					{
						currentHost->type = ADDR_NORMAL;
					}

					//给域名分配空间并赋值
					int len = strlen(name);
					currentHost->domainName = (char*)malloc(sizeof(char) * (len + 1));
					strcpy(currentHost->domainName, name);
					//要不要加个域名分配空间成功的判断??

					AddHostToTable(currentHost, name[0]);//根据域名的首字母将该主机添加进相应的Table中

				}
				else//如果转换失败则代表该IP地址不是合法有效的（因为地址族是有效的故不会发生出错返回结果为-1的情况）
				{
					printf("The IP is not valid.\n");

					//该host无效，释放掉分配的空间
					free(currentHost);
				}

			}
			else
				;//host节点的空间分配失败要干嘛？？

		}
	}
	else
	{
		printf("Failed to open the dnsrelay file(the file doesn't exist).\n");

		hostFile = fopen("./dnsrelay.txt", "w");//是否要创建一个文件？？？
	}

	fclose(hostFile);
}

void AddHostToTable(HOST_PTR currentHost, char initial)
{
	int tableSeq = GetTableSeq(initial);

	//更新队列情况
	if (hostTableFront[tableSeq] == NULL)//如果队头还是NULL，则代表队列是空的
	{
		hostTableFront[tableSeq] = currentHost;
		hostTableRear[tableSeq] = currentHost;
	}
	else//队列非空
	{
		hostTableRear[tableSeq]->nextHostPtr = currentHost;
		hostTableRear[tableSeq] = currentHost;
	}
	currentHost->nextHostPtr = NULL;
}

int InitDNSServer()//启动WSA加载套接字库,创建服务套接字并绑定端口
{
	WORD versionRequested = MAKEWORD(1, 1);
	WSADATA wsaData;
	int err = WSAStartup(versionRequested, &wsaData);//加载套接字库返回信息至err
	if (err != FALSE)
	{
		printf("WinSock failed to initialize\n");
		WSACleanup(); 
		return 1;
	}
	printf("WinSock initialized succesfully\n");

	serverSocket = socket(AF_INET, SOCK_DGRAM, 0);//创建服务器的套接字
	if (serverSocket == INVALID_SOCKET)
	{
		printf("Socket creation failed\n");
		WSACleanup();
		return 0;
	}
	printf("Socket created successfully\n");

	SOCKADDR_IN serverAddr;//定义server发送和接收数据包的地址
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//均为网络字节顺序

	err = bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(SOCKADDR));//绑定套接字
	if (err == SOCKET_ERROR)
	{
		printf("Binding failed with error: %d\n", err);
		WSACleanup();
		return 1;
	}
	printf("Binding successfully\n");
	return 0;
}
