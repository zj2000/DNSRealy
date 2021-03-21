#include"DNSHeader.h"

HOST_PTR hostTableFront[36]; //�ֱ����a-z��0-9��ͷ������
HOST_PTR hostTableRear[36]; //��ͷa-z��0-9������Դβָ��
CACHED_PTR cachedTableFront[36]; //�ֱ����a-z��0-9��ͷ������
CACHED_PTR cachedTableRear[36]; //��ͷa-z��0-9������Դβָ��
int hostCount[36];//������Դÿ�����ֵ���Դ��
int cachedCount[36];//������Դÿ�����ֵ���Դ��
BOOL isCachedOperateAvailable;//ͬʱֻ����һ���̶߳�cached��Դ���и�д���൱��mutex
REQUESTPool* requestPool;//�����
int requestCount;//�����������Ŀ
BOOL isPoolOperateAvailable;//ͬʱֻ����һ���̶߳��������Դ���и�д���൱��mutex
SOCKET serverSocket;//��������ͻ���ͨ���׽���
int newIdDistribute = 0;//�·���id������MAX_REQUEST������������ɱ���ػ�
int debugLevel = 0;//���Եȼ���1Ϊ�������2Ϊ����߳��ĵ�����Ϣ

int clientReqCount = 0;

int main(int argc, char** argv)
{
	//debugLevel = argc;
	//ȷ��������Ϣ����
	if (strcmp(argv[1], "-d") == 0)//������Ϣ����1�������ʱ�����꣬��ţ��ͻ���IP��ַ�� ��ѯ��������
	{
		debugLevel = 1;
	}
	else if (strcmp(argv[1], "-dd") == 0)//������Ϣ����2 ������߳��ĵ�����Ϣ��
	{
		debugLevel = 2;
	}
	else
	{
		debugLevel = 0; //�޵�����Ϣ���
	}
	printf("��ǰ������Ϣ�ȼ�Ϊ��%d\n", debugLevel);

	int err = 0, erro = 0;//����������Ϣ

	//��ʼ��������Դ�б�
	InitHostTable();
	InitCachedTable();
	InputHostFile();
	isPoolOperateAvailable = TRUE;
	isCachedOperateAvailable = TRUE;
	//��������������socket
	err = InitDNSServer(&serverSocket);
	if (err == 1)
	{
		printf("Failed to initialize DNSserver.\n");
		return 0;
	}

	requestPool = (REQUESTPool*)malloc(sizeof(REQUESTPool));//�����ͷ����ʼ������ռ�
	if (requestPool == NULL)
	{
		printf("Failed to malloc requestPool.\n");
		return 0;
	}
	requestPool->isAvailable = FALSE;//ͷ��ָ���һ�����󣬱���������
	requestPool->requestPtr = NULL;//��������������
	requestPool->nextRequestPtr = NULL;//ָ���һ��ָ����Ϊ��

	//�ĸ�������յ�������߳�,����ͬʱֻ���յ��ĸ�����ͬʱ�����ĸ������յ����������������pool��
	int first = 1, second = 2, third = 3, fourth = 4;
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &first);
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &second);
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &third);
	_beginthread((void(__cdecl*) (void*))HandleRequestThread, 0, &fourth);

	//������������غ���Դ�����Ľ���
	_beginthread((void(__cdecl*) (void*))FlushDnsCacheTTLThread, 0, NULL);
	_beginthread((void(__cdecl*) (void*))FlushDNSRequestTTLThread, 0, NULL);

	printf("Initialize Complete.\n\n");

	//���ܿͻ��˷���������
	while (TRUE)
	{
		char recvbuf[BUF_SIZE];
		/*char recvbuf[BUF_SIZE] = { 0x00, 0x02, 0x01, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
			0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03,
			0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};*/
			//���ܻ���
		int recvbuflen = BUF_SIZE, sendbuflen = BUF_SIZE;//����ռ��С
		struct sockaddr_in clientAddr;//�û���ַ
		int clientAddrLen = sizeof(clientAddr);//�û���ַ����

		memset(recvbuf, '\0', sizeof(recvbuf));//���ܻ�������
		ZeroMemory(&clientAddr, sizeof(clientAddr));//�ͻ���ַ����

		//�����׽��ֱ������
		DWORD lenReturned = 0;//ʵ�ʷ����ֽ���
		BOOL banNewBehav = FALSE;//������Ϣ
		DWORD status;
		status = WSAIoctl(serverSocket, _WSAIOW(IOC_VENDOR, 12),
			&banNewBehav, sizeof(banNewBehav),
			NULL, 0, &lenReturned,
			NULL, NULL);

		if (status == SOCKET_ERROR)
		{
			return 0;
		}

		//�������󣬷��������
		err = recvfrom(serverSocket, recvbuf, recvbuflen, 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
		int len = err;//���յĳ���
		if (err == SOCKET_ERROR) //�����쳣
		{

			erro = WSAGetLastError();//��ȡ�쳣����
			if (erro == WSAEWOULDBLOCK)//�������ݿɶ�
			{
				Sleep(20);
				continue;
			}
			else//��ȡ����ʧ��
			{
				printf("Failed to receive from client.\n");
				break;
			}
		}
		else//���������������ع������̴߳���
		{
			//printf("Bytes received from client: %d\n", err);
			//��������
			DNSRequest* newRequest;
			newRequest = (DNSRequest*)malloc(sizeof(DNSRequest));
			if (newRequest == NULL)
			{
				printf("Failed to malloc newRequest.\n");
				return;
			}
			//��������
			newRequest->seq = clientReqCount++;
			GetLocalTime(&newRequest->systemTime);//����ʱ��
			newRequest->clientAddr = clientAddr;
			newRequest->clientAddrLen = clientAddrLen;
			newRequest->isServed = FALSE;
			newRequest->ttl = REQUEST_TTL;
			newRequest->packet = MakeDNSPacket(recvbuf);

			err = AddDNSRequestToPool(newRequest);	//�����յ��Ŀͻ���������뵽���������
			if (err == -1)//������޷��ټ���������
				printf("Too many requests or malloc error. Current request failed to accept.\n");
			else
				;// printf("Request accepted successfully.\n");

			PrintDebugInfo(newRequest);
			if (debugLevel == 2)//����߳�������Ϣ
			{
				char clientIP[16];
				inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, 16);

				printf("���յ��ͻ��ˣ�IP:%s���˿�:%d�������������%d�ֽڣ���������������£�\n",
					clientIP, ntohs(clientAddr.sin_port), len);

				newRequest->packet->header->id = ntohs(*(UINT16*)recvbuf);
				PrintRecvPacketInfo(recvbuf, len, newRequest->packet->header);
			}
		}
	}
	//�ر��׽���
	closesocket(serverSocket);

	//�ر�winsocket��
	WSACleanup();
}

void HandleRequestThread(void* lpvoid)
{
	int id = *(int*)lpvoid;//�̱߳��
	char* upperDNSAddr = UPPER_DNS;//�ϲ�DNS IP��ַ
	printf("%d �Ŵ��������̴߳����ɹ�.\n", id);
	char* sendBuf;//���ͻ���
	int sendBufLen = BUF_SIZE;//���ͻ����С
	int err = 0;//����������Ϣ

	sendBuf = (char*)malloc(sendBufLen * sizeof(char));//Ϊ���ͻ������ռ�
	if (sendBuf == NULL)
	{
		printf("Failed to malloc sendbuf.\n");
		return;
	}

	//�����ϲ�DNS��ַ���Խ���ͨ��
	struct sockaddr_in servAddr;//�ϲ�dns��ַ
	ZeroMemory(&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(PORT);
	//��ipv4��ipv6��ַ�ڵ��ʮ���ƺͶ���������֮��ת��
	inet_pton(AF_INET, upperDNSAddr, &servAddr.sin_addr);

	//����������ַ�������ϲ�DNS������Ϣ
	struct sockaddr_in myAddr;
	ZeroMemory(&myAddr, sizeof(myAddr));
	myAddr.sin_family = AF_INET;
	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);//32λ����������˳��ת��Ϊ�����ֽ�˳��
	myAddr.sin_port = htons(UPPERPORT(id));//32λ������

	SOCKET upperDNSSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);//�������ϲ�dns����ͨ�ŵ�socket
	bind(upperDNSSocket, (struct sockaddr*)&myAddr, sizeof(myAddr));//��socket��ַ�˿�

	//�����׽��ֱ������
	DWORD lenReturned = 0;//ʵ�ʷ����ֽ���
	BOOL banNewBehav = FALSE;//������Ϣ
	WSAIoctl(upperDNSSocket, _WSAIOW(IOC_VENDOR, 12), &banNewBehav, sizeof(banNewBehav),
		NULL, 0, &lenReturned, NULL, NULL);

	_beginthread((void(__cdecl*) (void*))HandleReplyThread, 0, &upperDNSSocket);//�ȴ����ϲ�dns�Ļ�Ӧ

	//��������
	while (TRUE)
	{
		//���������ȡ�����Դ��������
		DNSRequest* request = NULL;
		while (request == NULL)
		{
			Sleep(20);
			request = GetDNSRequest();
		}

		DNSPacket* recvPacket = request->packet;

		//UINT32 ipAddress = 0;
		char* domainName = NULL;

		UINT32 ipAddress[30];//�ҵ���ip��ַ
		int count = 0;//�ڱ��أ���ʼ+���棩�ҵ��ĵ�ַ��

		//��ַ����ADDR_ERROR/ADDR_NORMAL/ADDR_NOT_FOUND
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

		//������ѯ��ַ״̬���д���
		switch (addrStatus)
		{
		case ADDR_ERROR:
		case ADDR_NORMAL:
		{
			//��ѯ����״̬��ӵ�dns������
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
				printf("%d���̹߳�����ӦDNS��ʧ��.\n", id);
				return;
			}
			resultPacket->header->id = request->oldID;

			//��DNS���ṹ��ת��Ϊ�ַ�����ʽ���뷢�ͻ���
			sendBuf = GetDNSPacketString(resultPacket, &sendBufLen);

			//���ͻ�Ӧ���ͻ���
			err = sendto(serverSocket, sendBuf, sendBufLen, 0, (struct sockaddr*)&(request->clientAddr), request->clientAddrLen);//���ͻ�Ӧ���ͻ���
			int len = err;
			if (err == SOCKET_ERROR)
				printf("%d���߳���ͻ��˷�����Ӧ��ʧ��.\n", id);
			else
			{
				//��ӡ������Ϣ
				if (debugLevel == 2)
				{
					char clientIP[16];
					inet_ntop(AF_INET, &request->clientAddr.sin_addr, clientIP, 16);

					printf("%d���߳���ͻ��ˣ�IP:%s���˿�:%d��������Ӧ������%d�ֽڣ�ID��[%d->%d]\n",
						id, clientIP, ntohs(request->clientAddr.sin_port),
						len, request->newID, request->oldID);
				}
			}

			DNSRequest* remove = FinishDNSRequestInPool(request->newID);//����������Ƴ�����
		}
		break;
		case ADDR_NOT_FOUND:
		{
			int len;//���Ͱ���С
			recvPacket->header->id = request->newID;
			sendBuf = GetDNSPacketString(recvPacket, &len);//��DNS���ṹ��ת��Ϊ�ַ�����ʽ���뷢�ͻ���

			//���Ͳ�ѯ�����ϲ�dns
			err = sendto(upperDNSSocket, sendBuf, len, 0, (struct sockaddr*)&servAddr, sizeof(servAddr));
			len = err;

			//��ӡ������Ϣ
			if (debugLevel == 2)
			{
				printf("\n%d���߳����ϲ�DNS��������IP:%s���˿�:%d���������������%d�ֽڣ�ID��[%d->%d]\n",
					id, upperDNSAddr, ntohs(servAddr.sin_port),
					len, request->oldID, request->newID);
			}

			//��ʱ����û�н������ط�upper dns����
			Sleep(UPPER_TIMEOUT);
			if (FinishDNSRequestInPool(request->newID) != NULL)
			{
				err = sendto(upperDNSSocket, sendBuf, len, 0, (struct sockaddr*)&servAddr, sizeof(servAddr));

				//��ӡ������Ϣ
				if (debugLevel == 2)
				{
					printf("\n���ϲ�DNS���������͵�����ʱ�������ط���\n");
					printf("%d���߳����ϲ�DNS��������IP:%s���˿�:%d���������������%d�ֽڣ�ID��[%d->%d]\n",
						id, upperDNSAddr, ntohs(servAddr.sin_port),
						len, request->oldID, request->newID);
				}
			}

			if (err == SOCKET_ERROR)
				printf("%d���߳����ϲ�DNS���������������ʧ��.\n", id);
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
		//�ϲ�DNS������Ϣ
		err = recvfrom(*upperDNSSocket, dnsbuf, dnsbuflen, 0, (struct sockaddr*)&servaddr, &servaddrlen);
		int len = err;
		if (err == SOCKET_ERROR)//�����쳣
		{
			erro = WSAGetLastError();//��ȡ�쳣����
			if (erro == WSAEWOULDBLOCK)//�������ݿɶ�
			{
				Sleep(20);
				continue;
			}
			else//��ȡ����ʧ��
			{
				if (debugLevel == 2)
				{
					printf("���ϲ�DNS������������Ӧʧ��.\n");
				}
				break;
			}
		}
		else//������Ϣ�ɹ�
		{
			//printf("Bytes %d received from upper DNS.\n", err);
			if (debugLevel == 2)//����߳�������Ϣ
			{
				printf("���յ��ϲ�DNS��������IP:%s���˿�:%d������Ӧ������%d�ֽڣ���Ӧ�����������£�\n",
					UPPER_DNS, ntohs(servaddr.sin_port), len);

				char* nextLoc = NULL;
				DNSHeader* header = GetHeaderStruct(dnsbuf, &nextLoc);
				PrintRecvPacketInfo(dnsbuf, len, header);
			}

			int newID = ntohs(*(u_short*)dnsbuf);//��ȡ��ǰu_short���ȵ�id��������˳���Ϊ����˳��
			DNSRequest* req = FinishDNSRequestInPool(newID);//����������ʶΪ�����

			if (req == NULL)
				printf("failed to remove request in pool.\n");
			else
			{
				//printf("remove request in pool.\n");
				*(u_short*)dnsbuf = htons(req->oldID);//����˳���Ϊ����˳��,������ŵĸ�Ϊ�ɱ��
				err = sendto(serverSocket, dnsbuf, dnsbuflen, 0, (struct sockaddr*)&(req->clientAddr), req->clientAddrLen);//�ϲ�dns��Ӧ���͵��ͻ���
				len = err;
				if (err == SOCKET_ERROR)
				{
					printf("failed to send reply to client.\n");
					erro = WSAGetLastError();
					printf("error %d.\n", erro);
				}
				else
				{
					//��ӡ������Ϣ
					if (debugLevel == 2)
					{
						char clientIP[16];
						inet_ntop(AF_INET, &req->clientAddr.sin_addr, clientIP, 16);

						printf("\n��ͻ��ˣ�IP:%s���˿�:%d��������Ӧ������%d�ֽڣ�ID��[%d->%d]\n",
							clientIP, ntohs(req->clientAddr.sin_port),
							len, req->newID, req->oldID);
					}
				}
			}
			HandleReplyPacket(dnsbuf);//�����ϲ�DNS��Ӧ�������Դ�������б�
		}
	}
}

int AddDNSRequestToPool(DNSRequest* request)	//�����յ��Ŀͻ���������뵽��������棬���ص�ǰ������Ŀ
{
	int i = 0;
	REQUESTPool* newPtr;
	while (!isPoolOperateAvailable)//��������ʱ����������ȡ
	{
		Sleep(100);
	}
	isPoolOperateAvailable = FALSE;//����

	//�������ͷ��ָ��ĵ�һ������ʼ�������Ѱ�ҵ����һ�����
	for (REQUESTPool* ptr = requestPool; i <= MAX_REQUEST && ptr != NULL; ptr = ptr->nextRequestPtr)
	{
		i++;
		if (ptr->nextRequestPtr == NULL)
		{
			newPtr = (REQUESTPool*)malloc(sizeof(REQUESTPool));//�������ؽ��
			if (newPtr == NULL)
			{
				printf("�����������ռ�ʧ��...\n");
				return -1;
			}
			else
				;

			requestCount++;//��ǰ��������������Ŀ����
			ptr->nextRequestPtr = newPtr;//����������������
			newPtr->isAvailable = TRUE;//��������
			newPtr->requestPtr = request;//�������
			newPtr->requestPtr->oldID = request->packet->header->id;//�����ԭID�����ͻ��˷��͵�dns�������ID��
			newPtr->requestPtr->newID = newIdDistribute;
			newIdDistribute++;
			newIdDistribute = newIdDistribute % MAX_REQUEST;//�·���ID����

			newPtr->nextRequestPtr = NULL;//β
			isPoolOperateAvailable = TRUE;//���������

			return i;//���ؼ���������֮�����������
		}
		else
			;
	}
	return -1;//������������������ʧ��
}


DNSRequest* GetDNSRequest()			//������������ȡ����ִ�е�����
{
	DNSRequest* retPtr = NULL;
	while (!isPoolOperateAvailable)//��������ʱ����������ȡ
	{
		Sleep(100);
	}
	isPoolOperateAvailable = FALSE;//����

	//�������ͷ��ָ��ĵ�һ������ʼ�������Ѱ�ҵ�һ����ִ�е�����
	for (REQUESTPool* ptr = requestPool->nextRequestPtr; ptr != NULL; ptr = ptr->nextRequestPtr)
	{
		//�ҵ�����ִ�е����󷵻�
		if (ptr->isAvailable)
		{
			ptr->isAvailable = FALSE;//�����߳̿�ʼ�������󣬹ʵ�ǰ�����󲻿���
			retPtr = ptr->requestPtr;
		}
	}
	isPoolOperateAvailable = TRUE;//���������
	return retPtr;//��û���ҵ�����ִ�еķ��ؿ�ָ��
}

DNSRequest* FinishDNSRequestInPool(int newID)
{
	DNSRequest* retPtr = NULL;
	while (!isPoolOperateAvailable)//��������ʱ����������ȡ
	{
		Sleep(100);
	}
	isPoolOperateAvailable = FALSE;//����

	//�������ͷ����ʼ���������Ѱ���ƶ�ID����
	for (REQUESTPool* ptr = requestPool; ptr->nextRequestPtr != NULL; ptr = ptr->nextRequestPtr)
	{
		//�ҵ�Ŀ�������ǰ������ɾ��Ŀ�������޸�����
		if (ptr->nextRequestPtr->requestPtr->newID == newID)
		{
			retPtr = ptr->nextRequestPtr->requestPtr;
			ptr->nextRequestPtr = ptr->nextRequestPtr->nextRequestPtr;
			requestCount--;
			break;
		}
	}
	isPoolOperateAvailable = TRUE;//���������
	return retPtr;//��û���ҵ�Ŀ�����󷵻ؿ�ָ��
}

void HandleReplyPacket(char* packet)//�����ϲ�dns��Ӧ�����cache�ĵ�ַ
{
	//dns��Ӧת��Ϊdns�ṹ�崦��
	DNSPacket* repPacket = MakeDNSPacket(packet);
	BOOL isCnameSingal = TRUE;
	char* cname = NULL;
	for (int i = 0; i < repPacket->header->anCount; i++)
	{
		if (repPacket->answers == NULL)
			continue;
		if (repPacket->answers[i].type != A && repPacket->answers[i].type != CNAME)//����A�����Ҳ���CNAME����
			continue;

		if (repPacket->answers[i].type == CNAME)//����CNAME
		{
			cname = GetNormalDomainName(repPacket->answers[i].name);
		}
		else
		{

			//���ϲ�dns�Ļ�Ӧ��ַ��ӵ�cache֮��
			CACHED_PTR newCached;
			newCached = (CACHED_PTR)malloc(sizeof(CACHED));
			if (newCached == NULL)
			{
				printf("Failed to malloc newCached.\n");
				return;
			}
			char* answersDomainName = GetNormalDomainName(repPacket->answers[i].name);
			char initial = answersDomainName[0];
			int tableSeq = GetTableSeq(initial);//Ѱ��cache����б���

			if (cachedCount[i] == MAX_CACHED)//���浽�����ޣ��޷��������
			{
				printf("Too many cached resources, cuurent resource fialed to be cached.\n");
				return;
			}

			//��ӻ�����Դ�б���
			while (!isCachedOperateAvailable)//��������ʱ���л������
			{
				Sleep(100);
			}
			isCachedOperateAvailable = FALSE;//����
			if (cachedTableFront[tableSeq] == NULL)//�����ͷ����NULL�����������ǿյ�
			{
				cachedTableFront[tableSeq] = newCached;
				cachedTableRear[tableSeq] = newCached;
			}
			else//���зǿ�
			{
				cachedTableRear[tableSeq]->nextCachedPtr = newCached;
				cachedTableRear[tableSeq] = newCached;
			}
			cachedCount[tableSeq]++;

			//������Դ��Ϣ
			int len = strlen(answersDomainName);
			newCached->domainName = (char*)malloc(sizeof(char) * (len + 1));//����������ռ�
			if (newCached->domainName == NULL)
			{
				printf("Failed to malloc newCached->domainName.\n");
				return;
			}
			strcpy(newCached->domainName, answersDomainName);//��������

			newCached->cName = cname;//�������
			newCached->ttl = CACHED_TTL;//����ttl
			newCached->nextCachedPtr = NULL;
			//inet_pton(AF_INET, repPacket->answers[i].rData, (PVOID)&newCached->ipAddress);//����IP
			newCached->ipAddress = ntohl(*((UINT32*)repPacket->answers[i].rData));

			isCachedOperateAvailable = TRUE;//����

			printf("�������������ݵ����أ� %s (CNAME��%s)\n", newCached->domainName, newCached->cName);
		}

	}
}

int getAddrStatus(char* addr, UINT32 ipAddr[30], int* count)//��ȡ�˵�ַ��״̬��error/cached/ notfound
{
	unsigned int i;
	int ipCount = 0;
	int status = ADDR_NOT_FOUND;
	int tableSeq = GetTableSeq(addr[0]);//�������ַ���Ӧ�ı���±�

	//��ʼ��
	for (i = 0; i < 30; i++)
	{
		ipAddr[i] = 0x0;
	}

	//���޷�ʶ��.��ת��Ϊ�ַ���.��
	for (i = 0; i < strlen(addr); i++)
	{
		if (addr[i] < 0x20)
			addr[i] = '.';
	}

	//�ڱ�����Դ�б��в���
	for (HOST_PTR ptr = hostTableFront[tableSeq]; ptr != NULL; ptr = ptr->nextHostPtr)
	{
		if (strcmp(ptr->domainName, addr) == 0)
		{
			ipAddr[ipCount] = ptr->ipAddress;//����IP
			ipCount++;//��������һ

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

	//�ڻ�����Դ�б��в���
	while (!isCachedOperateAvailable)//��������ʱ���л������
	{
		Sleep(100);
	}
	isCachedOperateAvailable = FALSE;//����
	for (CACHED_PTR ptr = cachedTableFront[tableSeq]; ptr != NULL; ptr = ptr->nextCachedPtr)
	{
		if (ptr->cName != NULL)
		{
			if ((strcmp(ptr->domainName, addr) == 0) || (strcmp(ptr->cName, addr) == 0))//�ҵ�ƥ��
			{
				ipAddr[ipCount] = ptr->ipAddress;//����IP
				ipCount++;//��������һ

				ptr->ttl = CACHED_TTL;//ˢ��ttl

				isCachedOperateAvailable = TRUE;//����
				status = ADDR_NORMAL;
			}
			else
				;
		}
		else
		{
			if (strcmp(ptr->domainName, addr) == 0)//�ҵ�ƥ��
			{
				ipAddr[ipCount] = ptr->ipAddress;//����IP
				ipCount++;//��������һ

				ptr->ttl = CACHED_TTL;//ˢ��ttl

				isCachedOperateAvailable = TRUE;//����
				status = ADDR_NORMAL;
			}
			else
				;
		}
	}
	isCachedOperateAvailable = TRUE;//����

	*count = ipCount;
	return status;
}

int getCNameStatus(char* name, char** domainName)
{
	int tableSeq = GetTableSeq(name[0]);
	/*
	//�ڻ�����Դ�б��в���
	while (!isCachedOperateAvailable)//��������ʱ���л������
	{
		Sleep(100);
	}
	isCachedOperateAvailable = FALSE;//����
	for (CACHED_PTR ptr = cachedTableFront[tableSeq]; ptr != NULL; ptr = ptr->nextCachedPtr)
	{
		if (strcmp(ptr->cName, name) == 0)//�ҵ�ƥ��
		{
			*domainName = (char*)malloc(sizeof(char) * (strlen(ptr->domainName + 1)));
			strcpy(*domainName, ptr->domainName);
			ptr->ttl = CACHED_TTL;//ˢ��ttl

			isCachedOperateAvailable = TRUE;//����
			return ADDR_NORMAL;
		}
	}
	isCachedOperateAvailable = TRUE;//����
	*/
	return ADDR_NOT_FOUND;
}

//������Ӧ��
DNSPacket* formDNSPacket(DNSPacket* clientPacket, UINT32 ipAddr[30], int addrStatus, int count)//���ݵ�ַblocked��cached���������DNS���ṹ��Ĵ���
{
	//׼������
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

	//���ݵ�ַ���ͽ���DNS��Ӧ������
	if (addrStatus == ADDR_ERROR)//���ε�ַ
	{
		retHeader->id = clientPacket->header->id;//��Ӧ����id���������ͬ
		retHeader->qr = 1;//1��ʾ��Ӧ
		retHeader->opCode = clientPacket->header->opCode;//��Ӧ����opcode�����������ͬ
		retHeader->aa = 0;
		retHeader->tc = 0;
		retHeader->rd = 1;
		retHeader->ra = 1;
		retHeader->rCode = 3;//Name Error��the domain name referenced in the query does not exist
		retHeader->qdCount = 0;
		retHeader->anCount = 0;
		retHeader->nsCount = 0;
		retHeader->arCount = 0;

		//DNS���ṹ��
		retPacket->header = retHeader;
		retPacket->queries = NULL;
		retPacket->answers = NULL;
		retPacket->authority = NULL;
		retPacket->additional = NULL;
	}
	else//������ַ
	{
		int i = 0;
		for (i = 0; i < count; i++)
		{
			//����DNS��Ӧ�ṹ��
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

			//ͷ��
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

			//DNS���ṹ��
			retPacket->header = retHeader;
			retPacket->queries = retQuestion;
			retPacket->answers = retResponse;
			retPacket->authority = NULL;
			retPacket->additional = NULL;
		}

	}
	return retPacket;
}
//�������cname����Ӧ��
DNSPacket* FormCNAMEPacket(DNSPacket* clientPacket, char* domainName)
{
	//׼������
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

	//����DNS��Ӧ�ṹ��
	retResponse->name = clientPacket->queries->qName;
	retResponse->type = CNAME;
	retResponse->rclass = clientPacket->queries->qClass;
	retResponse->ttl = 0x100;
	retResponse->rdLength = (UINT16)(strlen(domainName) + 1);
	retResponse->rData = GetDNSDomainName(domainName);

	//ͷ��
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

	//DNS���ṹ��
	retPacket->header = retHeader;
	retPacket->queries = retQuestion;
	retPacket->answers = retResponse;
	retPacket->authority = NULL;
	retPacket->additional = NULL;

	return retPacket;
}

void FlushDnsCacheTTLThread()		//��������cache��ַ��ʣ����Чʱ��
{

	while (1)
	{
		Sleep(10000);
		while (!isCachedOperateAvailable)//��������ʱ���л������
		{
			Sleep(100);
		}
		isCachedOperateAvailable = FALSE;//����
		for (int i = 0; i < 36; i++)
		{
			CACHED* prevPtr = NULL;
			prevPtr = (CACHED*)malloc(sizeof(CACHED));
			for (prevPtr->nextCachedPtr = cachedTableFront[i]; prevPtr != NULL && prevPtr->nextCachedPtr != NULL; prevPtr = prevPtr->nextCachedPtr)
			{
				prevPtr->nextCachedPtr->ttl -= 4;
				if (prevPtr->nextCachedPtr->ttl < 0)//ttlС���㣬ɾ��������
				{
					if (prevPtr->nextCachedPtr == cachedTableRear[i])//����β���
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
						free(waste);//�ͷſռ�
						waste = NULL;
					}
					
				}
				else
					;
			}
		}
		isCachedOperateAvailable = TRUE;//����
	}
}

void FlushDNSRequestTTLThread()	//����������������������ʣ����Чʱ��
{
	while (1)
	{
		Sleep(10000);
		while (!isPoolOperateAvailable)//��������ʱ���л������
		{
			Sleep(100);
		}
		isPoolOperateAvailable = FALSE;//����
		for (REQUESTPool* prevPtr = requestPool; prevPtr != NULL && prevPtr->nextRequestPtr != NULL; prevPtr = prevPtr->nextRequestPtr)
		{
			prevPtr->nextRequestPtr->requestPtr->ttl -= 4;
			if (prevPtr->nextRequestPtr->requestPtr->ttl < 0)//ttlС���㣬ɾ��������
			{
				REQUESTPool* waste = prevPtr->nextRequestPtr;
				prevPtr->nextRequestPtr = prevPtr->nextRequestPtr->nextRequestPtr;

				//�ͷſռ�
				FreePacketSpace(waste->requestPtr->packet);
				
				if (waste != NULL)
				{
					free(waste->requestPtr);
					waste->requestPtr = NULL;
					free(waste);//�ͷſռ�
					waste = NULL;
				}
				else
					;
			}
		}
		isPoolOperateAvailable = TRUE;//����
	}
}

int GetTableSeq(char initial)//���������±�
{
	int tableSeq = 0;
	if (initial >= '0' && initial <= '9')//�������������ĸ������
	{
		tableSeq = initial - '0';
	}
	else if (initial >= 'a' && initial <= 'z')//�������������ĸ��СдӢ��
	{
		tableSeq = initial - 'a' + 10;
	}
	else//�������������ĸ�Ǵ�дӢ��
	{
		tableSeq = initial - 'A' + 10;
	}
	return tableSeq;
}

//���ݵ�����Ϣ�����ӡ��Ӧ�ĵ�����Ϣ
void PrintDebugInfo(DNSRequest* req)
{
	if (debugLevel == 0)//�޵�����Ϣ���ֱ�ӷ���
	{
		return;
	}
	else//�е�����Ϣ���
	{
		//������Ϣ����1�������ʱ�����꣬��ţ��ͻ���IP��ַ�� ��ѯ������
		//��ӡ���
		if (debugLevel == 2)
		{
			printf("\n");
		}
		printf("\n%3d�� ", req->seq);

		//��ӡʱ�����꣺��-��-�� ʱ���֣��� �ͻ���IP:
		printf("%d-%d-%d %d:%d:%d  ",
			req->systemTime.wYear, req->systemTime.wMonth, req->systemTime.wDay,
			req->systemTime.wHour, req->systemTime.wMinute, req->systemTime.wSecond);

		//��ӡ�ͻ���IP��ַ
		char clientIP[16];
		inet_ntop(AF_INET, &req->clientAddr.sin_addr, clientIP, 16);
		printf("�ͻ���IP��%-16s ", clientIP);

		//��ӡ��ѯ������
		printf("��ѯ����:%s", GetNormalDomainName(req->packet->queries[0].qName));

		///������Ϣ����2�������type��class
		if (debugLevel == 2)
		{
			printf("  TYPE:%d  CLASS:%d", req->packet->queries[0].qType, req->packet->queries[0].qClass);

		}

		printf("\n");
	}
}

//���Լ���2�Ĳ�����Ϣ���������ݰ���
void PrintRecvPacketInfo(char* recv, int len, DNSHeader* header)
{
	//��ӡ���յ��ľ����dns��������

	//ʮ���������ݰ�����
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

	//ͷ����������
	printf("���У�Header�����������£�\n");
	printf("ID: %d\n", header->id);
	printf("QR: %d, OPCODE: %d, AA: %d, TC: %d, RD: %d, RA: %d, Z: %d, RCODE: %d\n",
		header->qr, header->opCode, header->aa, header->tc,
		header->rd, header->ra, header->z, header->rCode);
	printf("Questions: %d\n", header->qdCount);
	printf("Answer RRs: %d\n", header->anCount);
	printf("Authority RRs: %d\n", header->nsCount);
	printf("Additional RRs: %d\n", header->arCount);
}

//�ͷ�dns���ķ���ռ䣬��������ʱpacketָ��NULL
void FreePacketSpace(DNSPacket* packet)
{
	if (packet == NULL)
		return;

	//�ͷ���ص����пռ䣬ע�������ϵ�ͷ�˳��
	UINT16 qdCount = packet->header->qdCount;
	UINT16 anCount = packet->header->anCount;
	UINT16 nsCount = packet->header->nsCount;
	UINT16 arCount = packet->header->arCount;
	UINT16 i = 0;

	//���ͷ�����ָ���еİ�ָ��ָ�����Դ
	//�ͷ�ͷ��
	free(packet->header);
	packet->header = NULL;

	//�ͷ�query����
	for (i = 0; i < qdCount; i++)
	{
		free(packet->queries[i].qName);
		packet->queries[i].qName = NULL;
	}
	free(packet->queries);
	packet->queries = NULL;

	//�ͷ�answers����
	for (i = 0; i < anCount; i++)
	{
		free(packet->answers[i].name);
		free(packet->answers[i].rData);
		packet->answers[i].name = NULL;
		packet->answers[i].rData = NULL;
	}
	free(packet->answers);
	packet->answers = NULL;

	//�ͷ�authority����
	for (i = 0; i < nsCount; i++)
	{
		free(packet->authority[i].name);
		free(packet->authority[i].rData);
		packet->authority[i].name = NULL;
		packet->authority[i].rData = NULL;
	}
	free(packet->authority);
	packet->authority = NULL;

	//�ͷ�additional����
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