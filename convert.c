#include"DNSHeader.h"

//�ַ�����û�������ֽ���������ֽ�������⣿��������δ����������

DNSHeader* GetHeaderStruct(char* headerStartLoc, char** nextStartLoc)//dnsͷ�ַ�ת��Ϊdnsͷ�ṹ��
{
	DNSHeader* packetHeader = NULL;
	packetHeader = (DNSHeader*)malloc(sizeof(DNSHeader));
	if (packetHeader != NULL)
	{
		UINT16* curHandleLoc = (UINT16*)headerStartLoc;//��ǰ������header��λ�ã�ÿ�δ���16λ
		UINT16 curHandleData = ntohs(*curHandleLoc);//��ǰ������λ��������������,ע��ת���������ֽ���

		//����id����
		packetHeader->id = curHandleData;
		curHandleData = ntohs(*(++curHandleLoc));//���µ�ǰ�����λ�ú�����

		//����flag����,��ȷ��λ��Ҫ��λ�����λ
		packetHeader->qr = (curHandleData & (0x8000)) >> 15;		//���� 1000 0000 0000 0000
		packetHeader->opCode = (curHandleData & (0x7800)) >> 11;	//���� 0111 1000 0000 0000
		packetHeader->aa = (curHandleData & (0x0400)) >> 10;		//���� 0000 0100 0000 0000
		packetHeader->tc = (curHandleData & (0x0200)) >> 9;			//���� 0000 0010 0000 0000
		packetHeader->rd = (curHandleData & (0x0100)) >> 8;			//���� 0000 0001 0000 0000
		packetHeader->ra = (curHandleData & (0x0080)) >> 7;			//���� 0000 0000 1000 0000
		packetHeader->z = (curHandleData & (0x0070)) >> 4;			//���� 0000 0000 0111 0000
		packetHeader->rCode = curHandleData & (0x000F);				//���� 0000 0000 0000 1111

		//����question section���������
		curHandleData = ntohs(*(++curHandleLoc));//���µ�ǰ�����λ�ú�����
		packetHeader->qdCount = curHandleData;

		//����answer section��RR����
		curHandleData = ntohs(*(++curHandleLoc));//���µ�ǰ�����λ�ú�����
		packetHeader->anCount = curHandleData;

		//����authority records section��RR����
		curHandleData = ntohs(*(++curHandleLoc));//���µ�ǰ�����λ�ú�����
		packetHeader->nsCount = curHandleData;

		//����additional records section��RR����
		curHandleData = ntohs(*(++curHandleLoc));//���µ�ǰ�����λ�ú�����
		packetHeader->arCount = curHandleData;

		//����ָ�룬�޸�һ��ָ����ָ��ĵ�ַ���˴��޸�Ϊ ��һ���֣���ѯ�������� ���׵�ַ
		curHandleLoc++;
		*nextStartLoc = (char*)curHandleLoc;
	}
	else
		;

	return packetHeader;
}

void MakeQueryStruct(QUESTION* packetQuery, char* queryStartLoc, char** nextStartLoc)	//dns������ַ�ת��Ϊdns����νṹ��
{
	//�ȴ���qName����
	int nameLen = 0;
	//queryStartLoc++;
	while (*(queryStartLoc + nameLen) != '\0')//�����������ȣ�������'\0'��������־
	{
		nameLen++;
	}
	nameLen++;//��'\0'Ԥ��һ��λ��

	//�����������ȷ���ռ�
	packetQuery->qName = NULL;
	packetQuery->qName = (char*)malloc(sizeof(char) * nameLen);
	if (packetQuery->qName != NULL)//�����ռ����ɹ�
	{
		strcpy(packetQuery->qName, queryStartLoc);//������������\0������

		//����qType����		
		queryStartLoc += nameLen;//����ָ��λ��			//��������Ϊʲô�Ǹ��˵�++nameLen????????
		UINT16* curHandleLoc = (UINT16*)(queryStartLoc);//��ǰ������query��λ�ã�ÿ�δ���16λ      
		UINT16 curHandleData = ntohs(*curHandleLoc);//��ǰ������λ��������������,ע��ת���������ֽ���
		packetQuery->qType = curHandleData;

		//����qClass����
		curHandleData = ntohs(*(++curHandleLoc));//���µ�ǰ�����λ�ú�����
		packetQuery->qClass = curHandleData;

		//����ָ�룬�޸�һ��ָ����ָ��ĵ�ַ���˴��޸�Ϊ ��һ���֣��ش��������� ���׵�ַ
		curHandleLoc++;
		*nextStartLoc = (char*)curHandleLoc;
	}
	else
	{
		////�����ռ����ʧ�ܴ����ͷſռ䣬����NULL ����
		//free(packetQuery);
		//packetQuery = NULL;
	}
}

void MakeRRStruct(RR* packetResponse, char* responseStartLoc, char* headerStartLoc, char** nextStartLoc)	//dns��Ӧ���ַ�ת��Ϊdns��Ӧ�νṹ��
{
	/*
		�ȴ���name����,һ����ǩһ����ǩ��������Ҫע���Ƿ���ѹ����������ǩ
		�����ĸ�����ǩ�У���ǩ��11��ͷ����ѹ�����ı�ǩ����00��ͷ����δѹ���ı�ǩ����Ϊ��ǩ���ȡ�63�ֽڣ�
		�������ܳ��ֵ����ֱ����ʽ��
			- a sequence of labels ending in a zero octet
			- a pointer
			- a sequence of labels ending with a pointer
	*/
	int nameLen = 0;		//�����ܳ��ȣ����ڷ���ռ�
	char domainName[256];	//��ʱ�洢����
	char* curLabelLoc = responseStartLoc;//��ǰָ���������ǩ
	UINT16* pointer = NULL;
	UINT16* firstJumpLoc = NULL;
	BOOL isCompressed = FALSE;//����Ƿ�ѹ��

	while (*curLabelLoc)//ÿ��ѭ������һ����ǩ��pointer,���һ����ǩ ֵΪ0�޷�����
	{
		//ͨ��λ�����ж��Ƿ���ѹ������Ϣ
		if (((*curLabelLoc) & 0xC0) == 0xC0)//��ѹ������Ϣpointer
		{
			if (isCompressed == FALSE)//�ǵ�һ����ת,�����ж����ת�����
			{
				isCompressed = TRUE;
				firstJumpLoc = (UINT16*)curLabelLoc;
			}
			
			pointer = (UINT16*)curLabelLoc;
			UINT16 offset = ntohs(*pointer) & 0x3FFF;//ѹ������Ϣ�����ͷ����ƫ����

			curLabelLoc = headerStartLoc + offset;//��ת��ƫ������ָ���ַ
		}
		else//����ͨ��label����ʽ����ǩ����+��ǩ����
		{
			int labelLen = *curLabelLoc;
			curLabelLoc++;//ָ���ǩ���ݵĵ�һ���ֽ�
			domainName[nameLen++] = labelLen;

			int i;
			for (i = 0; i < labelLen; i++)
			{
				domainName[nameLen++] = *curLabelLoc;
				curLabelLoc++;//ָ����һ���ֽ�
			}
		}
		if (curLabelLoc == NULL)
			break;
	}
	//��������0��ǩ
	domainName[nameLen++] = '\0';

	//��ת���õ��������浽�ṹ����
	packetResponse->name = NULL;
	packetResponse->name = (char*)malloc(sizeof(char) * nameLen);
	if (packetResponse->name != NULL)
	{
		strcpy(packetResponse->name, domainName);
	}
	else;

	//���µ�ǰ�����RR��λ��
	UINT16* curHandleLoc = NULL;
	if (isCompressed == FALSE)
	{
		curLabelLoc++;
		curHandleLoc = (UINT16*)(curLabelLoc);
	}
	else
	{
		curHandleLoc = firstJumpLoc + 1;
	}

	//���� type, rclass, ttl, rdLength
	packetResponse->type = ntohs(*curHandleLoc);
	packetResponse->rclass = ntohs(*(++curHandleLoc));
	packetResponse->ttl = (UINT32)ntohs(*((UINT32*)(++curHandleLoc)));
	curHandleLoc += 2;
	packetResponse->rdLength = ntohs(*curHandleLoc);
	curHandleLoc++;

	//����rData
	if (packetResponse->rdLength > 10000)
		return;
	packetResponse->rData = (char*)malloc(sizeof(char) * (packetResponse->rdLength + 1));
	if (packetResponse->rData != NULL)
	{
		memcpy(packetResponse->rData, (char*)curHandleLoc, packetResponse->rdLength);
		packetResponse->rData[packetResponse->rdLength] = '\0';
	}
	else;

	*nextStartLoc = (char*)curHandleLoc + packetResponse->rdLength;

}

char* GetHeaderString(DNSHeader* header)	//dnsͷ�ṹ��ת��Ϊdnsͷ�ַ�
{
	char* headerString = NULL;
	headerString = (char*)malloc(sizeof(char) * (1 + DNS_HEADER_LEN));//����ռ�
	if (headerString != NULL)
	{
		UINT16* curHandleLoc = (UINT16*)headerString;

		//ת��id
		*(curHandleLoc++) = htons(header->id);

		//ת��flag,��λ��ƴ�ӳ�������flag
		UINT16 flag = 0;
		flag |= (header->qr << 15);
		flag |= (header->opCode << 11);
		flag |= (header->aa << 10);
		flag |= (header->tc << 9);
		flag |= (header->rd << 8);
		flag |= (header->ra << 7);
		flag |= (header->z << 4);
		flag |= header->rCode;
		*(curHandleLoc++) = htons(flag);

		//ת��qdCount, anCount, nsCount, arCount
		*(curHandleLoc++) = htons(header->qdCount);
		*(curHandleLoc++) = htons(header->anCount);
		*(curHandleLoc++) = htons(header->nsCount);
		*(curHandleLoc) = htons(header->arCount);

		headerString[DNS_HEADER_LEN] = '\0';//���ַ����Ӹ���ֹ��
	}
	else
		;

	return headerString;
}

char* GetQueryString(QUESTION* query)//dns����νṹ��ת��Ϊdns������ַ�
{
	int nameLen = strlen(query->qName) + 1;//+1�ǰ�������ֹ��'\0'

	char* queryString = NULL;
	queryString = (char*)malloc(sizeof(char) * (nameLen + 5));//����Ŀռ��СΪqName+qType(2)+qClass(2)+'\0'(1)
	if (queryString != NULL)
	{
		//ת��qName
		strcpy(queryString, query->qName);//�и���ֹ��

		//ת��qType, qClass
		UINT16* curHandleLoc = (UINT16*)&queryString[nameLen];
		*curHandleLoc = htons(query->qType);
		*(++curHandleLoc) = htons(query->qClass);

		queryString[nameLen + 4] = '\0';//���ַ����Ӹ���ֹ��
	}
	else
		;

	return queryString;
}

char* GetRRString(RR* response)	//dns��Ӧ�νṹ��ת��Ϊdns��Ӧ���ַ�
{
	int nameLen = strlen(response->name) + 1;//������ֹ������������
	int totalRRLen = nameLen + 10 + (int)response->rdLength + 1;//10=type(2)+rdLength(2)+rclass(2)+ttl(4)

	char* responseString = NULL;
	responseString = (char*)malloc(sizeof(char) * totalRRLen);
	if (responseString != NULL)
	{
		//ת��name
		strcpy(responseString, response->name);//��\0

		//ת��type, rclass, ttl, rdLength
		UINT16* curHandleLoc = (UINT16*)&responseString[nameLen];
		*curHandleLoc = htons(response->type);
		curHandleLoc++;
		*curHandleLoc = htons(response->rclass);
		curHandleLoc++;
		*((UINT32*)curHandleLoc) = htons(response->ttl);
		curHandleLoc += 2;
		*curHandleLoc = htons(response->rdLength);
		curHandleLoc++;

		//ת��rData
		memcpy((char*)curHandleLoc, response->rData, (size_t)response->rdLength);

		responseString[totalRRLen - 1] = '\0';
	}
	else
		;

	return responseString;
}

DNSPacket* MakeDNSPacket(char* recvString)//��dns�ַ������dns���ṹ�����Է���
{
	DNSPacket* newPacket = NULL;
	newPacket = (DNSPacket*)malloc(sizeof(DNSPacket));//�ȷ���ռ�
	if (newPacket != NULL)//���ռ����ɹ�
	{
		newPacket->queries = NULL;
		newPacket->answers = NULL;
		newPacket->authority = NULL;
		newPacket->additional = NULL;

		char* curStartLoc = recvString;//��ǰ����������׵�ַ
		char* nextStartLoc = NULL;//��һ��Ҫ�����������׵�ַ

		//�ȴ���header���򣬴��ַ�����ת����header�ṹ
		newPacket->header = GetHeaderStruct(curStartLoc, &nextStartLoc);
		curStartLoc = nextStartLoc;//���µ�ǰ����������׵�ַ

		if (newPacket->header != NULL)//����ֵ��Ϊ�ռ�Ϊת���ɹ�
		{
			UINT16 i;//forѭ������
			UINT16 size;//Ҫĳ����Ҫ����Ŀռ��С

			//�����ѯ�������򣬴��ַ�����ת����QUESTION�ṹ
			size = newPacket->header->qdCount;
			if (size > 0 && *curStartLoc)
			{
				newPacket->queries = (QUESTION*)malloc(sizeof(QUESTION) * size);
				for (i = 0; i < size && *curStartLoc; i++)
				{
					MakeQueryStruct(&newPacket->queries[i], curStartLoc, &nextStartLoc);
					curStartLoc = nextStartLoc;
				}
			}
			else;

			//����ش��������򣬴��ַ�����ת����RR�ṹ
			size = newPacket->header->anCount;
			if (size > 0 && *curStartLoc)
			{
				newPacket->answers = (RR*)malloc(sizeof(RR) * size);
				for (i = 0; i < size && *curStartLoc; i++)
				{
					MakeRRStruct(&newPacket->answers[i], curStartLoc, recvString, &nextStartLoc);
					curStartLoc = nextStartLoc;
				}
			}
			else;

			//����Ȩ�����Ʒ��������򣬴��ַ�����ת����RR�ṹ
			size = newPacket->header->nsCount;
			if (size > 0 && *curStartLoc)
			{
				newPacket->authority = (RR*)malloc(sizeof(RR) * size);
				for (i = 0; i < size && *curStartLoc; i++)
				{
					MakeRRStruct(&newPacket->authority[i], curStartLoc, recvString, &nextStartLoc);
					curStartLoc = nextStartLoc;
				}
			}
			else;

			//��������Ϣ���򣬴��ַ�����ת����RR�ṹ
			size = newPacket->header->arCount;
			if (size > 0 && *curStartLoc)
			{
				newPacket->additional = (RR*)malloc(sizeof(RR) * size);
				for (i = 0; i < size && *curStartLoc; i++)
				{
					MakeRRStruct(&newPacket->additional[i], curStartLoc, recvString, &nextStartLoc);
					curStartLoc = nextStartLoc;
				}
			}
			else;
		}
		else
			;
	}
	else
		;

	return newPacket;
}

char* GetDNSPacketString(DNSPacket* packet, int* len)//��dns���ṹ�����ַ������Է���
{
	int queryLen = 0;
	int responseLen = 0;
	int totalLen = 0;

	char* headerString = GetHeaderString(packet->header);//Ҫ��Ҫ�пգ�����
	char** queryString = NULL;
	char** reponseString = NULL;

	UINT16 i;
	UINT16 size;
	//ת��query����
	size = packet->header->qdCount;
	if (size > 0)
	{
		queryString = (char**)malloc(sizeof(char*) * size);
		for (i = 0; i < size; i++)
		{
			queryString[i] = GetQueryString(&packet->queries[i]);
			queryLen += strlen(queryString[i]) + 5;//strlen(queryString[i])���ֻ��qName�Ĳ��֣���Ϊ��'\0'��,5= 2+2+1(\0)
			//queryLen += strlen(packet->queries[i].qName) + 5;
		}
	}

	size = packet->header->anCount + packet->header->nsCount + packet->header->arCount;//rr���ֵĸ�������
	int* eachRRLen = (int*)malloc(sizeof(int) * size);
	if (size > 0)
	{
		reponseString = (char**)malloc(sizeof(char*) * size);
		int count = 0;

		for (i = 0; i < packet->header->anCount && count < size; i++)//ת��answers����
		{
			reponseString[count] = GetRRString(&packet->answers[i]);
			eachRRLen[count] = strlen(packet->answers[i].name) + 11 + (int)packet->answers[i].rdLength;//11=type(2)+rdLength(2)+rclass(2)+ttl(4)+\0
			responseLen += eachRRLen[count];
			count++;
		}
		for (i = 0; i < packet->header->nsCount && count < size; i++)//ת��authority����
		{
			reponseString[count] = GetRRString(&packet->authority[i]);
			eachRRLen[count] = strlen(packet->authority[i].name) + 11 + (int)packet->authority[i].rdLength;//11=type(2)+rdLength(2)+rclass(2)+ttl(4)+\0
			responseLen += eachRRLen[count];
			count++;
		}
		for (i = 0; i < packet->header->arCount && count < size; i++)//ת��additional����
		{
			reponseString[count] = GetRRString(&packet->additional[i]);
			eachRRLen[count] = strlen(packet->additional[i].name) + 11 + (int)packet->additional[i].rdLength;//11=type(2)+rdLength(2)+rclass(2)+ttl(4)+\0
			responseLen += eachRRLen[count];
			count++;
		}
	}

	totalLen = DNS_HEADER_LEN + queryLen + responseLen;
	char* packetString = (char*)malloc(sizeof(char) * (totalLen + 1));

	//ƴ�Ӹ������ֱ��һ�������İ��ַ���
	int offset = 0;
	memcpy(&packetString[offset], headerString, DNS_HEADER_LEN);//header
	offset += DNS_HEADER_LEN;

	for (i = 0; i < packet->header->qdCount; i++)//query
	{
		int stringLen = strlen(queryString[i]) + 5;
		memcpy(&packetString[offset], queryString[i], stringLen);
		offset += stringLen;
	}
	for (i = 0; i < size; i++)//response
	{
		int stringLen = eachRRLen[i];
		memcpy(&packetString[offset], reponseString[i], stringLen);
		offset += stringLen;
	}
	packetString[totalLen++] = '\0';

	*len = totalLen;
	return packetString;
}

char* GetNormalDomainName(char* DNSDomainName)//��dns��ʽ������ת���ɳ�����ʽ������
{
	char tempResult[256];
	char* curHandleLoc = DNSDomainName;
	int offset = 0;
	int labelLen = *curHandleLoc;

	//if ((DNSDomainName[0] >= 'A' && DNSDomainName[0] <= 'Z')
	//	|| (DNSDomainName[0] >= 'a' && DNSDomainName[0] <= 'z')
	//	|| (DNSDomainName[0] >= '0' && DNSDomainName[0] <= '9'))
	//{
	//	//�����ǳ�����ʽ������ֱ�ӷ���
	//	return DNSDomainName;
	//}

	while (labelLen)
	{
		curHandleLoc++;//ָ���ǩ���ݵĵ�һ���ַ�
		int i = 0;
		for (i = 0; i < labelLen; i++)
		{
			tempResult[offset] = *curHandleLoc;
			offset++;//ƫ����ָ����һ��λ��
			curHandleLoc++;//��ǰ����ָ����һ���ַ�
		}
		labelLen = *curHandleLoc;//������һ����ǩ�����±�ǩ����Ϊ��һ����ǩ�ĳ���

		if (labelLen != 0)//����һ����ǩ���Ȳ�Ϊ0,��������δ������������������ӷָ�����.��
		{
			tempResult[offset] = '.';
			offset++;
		}
		else//����Ϊ������������ַ���������ֹ��'\0'
		{
			tempResult[offset] = '\0';
		}
	}

	int len = strlen(tempResult);
	char* normalDomainName = (char*)malloc(sizeof(char) * (len + 1));
	strcpy(normalDomainName, tempResult);

	return normalDomainName;
}

char* GetDNSDomainName(char* normalDomainName)//�ѳ�����ʽ������ת����dns��ʽ������
{
	char tempResult[256];
	char* curHandleLoc = normalDomainName;
	UINT8 labelStartLoc = 0;//��ǩ��ʼ�ĵط�����¼��ǩ���ȵ��Ǹ��ֽڵ�λ�ã�

	while (*curHandleLoc != '\0')
	{
		UINT8 labelLen = 0;
		while ((*curHandleLoc != '\0') && (*curHandleLoc != '.'))//û�ж���'.'����һ����ǩ��û�ж���
		{
			labelLen++;
			tempResult[labelStartLoc + labelLen] = *curHandleLoc;
			curHandleLoc++;
		}
		tempResult[labelStartLoc] = labelLen;
		labelStartLoc += labelLen + 1;//���±�ǩ��ʼ�ĵط�
	}
	tempResult[labelStartLoc] = '\0';

	int len = strlen(tempResult);
	char* DNSDomainName = (char*)malloc(sizeof(char) * (len + 1));
	strcpy(DNSDomainName, tempResult);

	return DNSDomainName;
}