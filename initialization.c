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
	if (hostFile != NULL)//����򿪳ɹ�
	{
		char ipAddrString[16], name[256];
		while (fscanf(hostFile, "%s%s", ipAddrString, name) != EOF)//�ļ���δ��ȡ����
		{
			HOST_PTR currentHost = (HOST_PTR)malloc(sizeof(HOST));
			if (currentHost != NULL)//�ռ����ɹ�
			{
				IN_ADDR ipAddr;
				int isValid = inet_pton(AF_INET, ipAddrString, (PVOID)&ipAddr);//�ѵ��ʮ�����ַ���ת���ɶ���������
				if (isValid == 1)//���ת���ɹ�
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

					//����������ռ䲢��ֵ
					int len = strlen(name);
					currentHost->domainName = (char*)malloc(sizeof(char) * (len + 1));
					strcpy(currentHost->domainName, name);
					//Ҫ��Ҫ�Ӹ���������ռ�ɹ����ж�??

					AddHostToTable(currentHost, name[0]);//��������������ĸ����������ӽ���Ӧ��Table��

				}
				else//���ת��ʧ��������IP��ַ���ǺϷ���Ч�ģ���Ϊ��ַ������Ч�Ĺʲ��ᷢ�������ؽ��Ϊ-1�������
				{
					printf("The IP is not valid.\n");

					//��host��Ч���ͷŵ�����Ŀռ�
					free(currentHost);
				}

			}
			else
				;//host�ڵ�Ŀռ����ʧ��Ҫ�����

		}
	}
	else
	{
		printf("Failed to open the dnsrelay file(the file doesn't exist).\n");

		hostFile = fopen("./dnsrelay.txt", "w");//�Ƿ�Ҫ����һ���ļ�������
	}

	fclose(hostFile);
}

void AddHostToTable(HOST_PTR currentHost, char initial)
{
	int tableSeq = GetTableSeq(initial);

	//���¶������
	if (hostTableFront[tableSeq] == NULL)//�����ͷ����NULL�����������ǿյ�
	{
		hostTableFront[tableSeq] = currentHost;
		hostTableRear[tableSeq] = currentHost;
	}
	else//���зǿ�
	{
		hostTableRear[tableSeq]->nextHostPtr = currentHost;
		hostTableRear[tableSeq] = currentHost;
	}
	currentHost->nextHostPtr = NULL;
}

int InitDNSServer()//����WSA�����׽��ֿ�,���������׽��ֲ��󶨶˿�
{
	WORD versionRequested = MAKEWORD(1, 1);
	WSADATA wsaData;
	int err = WSAStartup(versionRequested, &wsaData);//�����׽��ֿⷵ����Ϣ��err
	if (err != FALSE)
	{
		printf("WinSock failed to initialize\n");
		WSACleanup(); 
		return 1;
	}
	printf("WinSock initialized succesfully\n");

	serverSocket = socket(AF_INET, SOCK_DGRAM, 0);//�������������׽���
	if (serverSocket == INVALID_SOCKET)
	{
		printf("Socket creation failed\n");
		WSACleanup();
		return 0;
	}
	printf("Socket created successfully\n");

	SOCKADDR_IN serverAddr;//����server���ͺͽ������ݰ��ĵ�ַ
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//��Ϊ�����ֽ�˳��

	err = bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(SOCKADDR));//���׽���
	if (err == SOCKET_ERROR)
	{
		printf("Binding failed with error: %d\n", err);
		WSACleanup();
		return 1;
	}
	printf("Binding successfully\n");
	return 0;
}
