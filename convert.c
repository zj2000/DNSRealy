#include"DNSHeader.h"

//字符串有没有主机字节序和网络字节序的问题？？？？暂未处理。。。。

DNSHeader* GetHeaderStruct(char* headerStartLoc, char** nextStartLoc)//dns头字符转换为dns头结构体
{
	DNSHeader* packetHeader = NULL;
	packetHeader = (DNSHeader*)malloc(sizeof(DNSHeader));
	if (packetHeader != NULL)
	{
		UINT16* curHandleLoc = (UINT16*)headerStartLoc;//当前处理到的header的位置，每次处理16位
		UINT16 curHandleData = ntohs(*curHandleLoc);//当前处理到的位置上所含的数据,注意转换成主机字节序

		//处理id部分
		packetHeader->id = curHandleData;
		curHandleData = ntohs(*(++curHandleLoc));//更新当前处理的位置和数据

		//处理flag部分,精确到位需要按位与和移位
		packetHeader->qr = (curHandleData & (0x8000)) >> 15;		//掩码 1000 0000 0000 0000
		packetHeader->opCode = (curHandleData & (0x7800)) >> 11;	//掩码 0111 1000 0000 0000
		packetHeader->aa = (curHandleData & (0x0400)) >> 10;		//掩码 0000 0100 0000 0000
		packetHeader->tc = (curHandleData & (0x0200)) >> 9;			//掩码 0000 0010 0000 0000
		packetHeader->rd = (curHandleData & (0x0100)) >> 8;			//掩码 0000 0001 0000 0000
		packetHeader->ra = (curHandleData & (0x0080)) >> 7;			//掩码 0000 0000 1000 0000
		packetHeader->z = (curHandleData & (0x0070)) >> 4;			//掩码 0000 0000 0111 0000
		packetHeader->rCode = curHandleData & (0x000F);				//掩码 0000 0000 0000 1111

		//处理question section的问题个数
		curHandleData = ntohs(*(++curHandleLoc));//更新当前处理的位置和数据
		packetHeader->qdCount = curHandleData;

		//处理answer section的RR个数
		curHandleData = ntohs(*(++curHandleLoc));//更新当前处理的位置和数据
		packetHeader->anCount = curHandleData;

		//处理authority records section的RR个数
		curHandleData = ntohs(*(++curHandleLoc));//更新当前处理的位置和数据
		packetHeader->nsCount = curHandleData;

		//处理additional records section的RR个数
		curHandleData = ntohs(*(++curHandleLoc));//更新当前处理的位置和数据
		packetHeader->arCount = curHandleData;

		//二级指针，修改一级指针所指向的地址，此处修改为 下一部分：查询问题区域 的首地址
		curHandleLoc++;
		*nextStartLoc = (char*)curHandleLoc;
	}
	else
		;

	return packetHeader;
}

void MakeQueryStruct(QUESTION* packetQuery, char* queryStartLoc, char** nextStartLoc)	//dns请求段字符转换为dns请求段结构体
{
	//先处理qName部分
	int nameLen = 0;
	//queryStartLoc++;
	while (*(queryStartLoc + nameLen) != '\0')//计算域名长度，域名以'\0'做结束标志
	{
		nameLen++;
	}
	nameLen++;//给'\0'预留一个位置

	//根据域名长度分配空间
	packetQuery->qName = NULL;
	packetQuery->qName = (char*)malloc(sizeof(char) * nameLen);
	if (packetQuery->qName != NULL)//域名空间分配成功
	{
		strcpy(packetQuery->qName, queryStartLoc);//复制域名到‘\0’结束

		//处理qType部分		
		queryStartLoc += nameLen;//更新指针位置			//？？？？为什么那个人的++nameLen????????
		UINT16* curHandleLoc = (UINT16*)(queryStartLoc);//当前处理到的query的位置，每次处理16位      
		UINT16 curHandleData = ntohs(*curHandleLoc);//当前处理到的位置上所含的数据,注意转换成主机字节序
		packetQuery->qType = curHandleData;

		//处理qClass部分
		curHandleData = ntohs(*(++curHandleLoc));//更新当前处理的位置和数据
		packetQuery->qClass = curHandleData;

		//二级指针，修改一级指针所指向的地址，此处修改为 下一部分：回答问题区域 的首地址
		curHandleLoc++;
		*nextStartLoc = (char*)curHandleLoc;
	}
	else
	{
		////域名空间分配失败处理：释放空间，返回NULL ？？
		//free(packetQuery);
		//packetQuery = NULL;
	}
}

void MakeRRStruct(RR* packetResponse, char* responseStartLoc, char* headerStartLoc, char** nextStartLoc)	//dns回应段字符转换为dns回应段结构体
{
	/*
		先处理name部分,一个标签一个标签来处理，需要注意是否有压缩的域名标签
		域名的各个标签中，标签以11开头的是压缩过的标签，以00开头的是未压缩的标签（因为标签长度≤63字节）
		域名可能出现的三种表达形式：
			- a sequence of labels ending in a zero octet
			- a pointer
			- a sequence of labels ending with a pointer
	*/
	int nameLen = 0;		//域名总长度，用于分配空间
	char domainName[256];	//暂时存储域名
	char* curLabelLoc = responseStartLoc;//当前指向的域名标签
	UINT16* pointer = NULL;
	UINT16* firstJumpLoc = NULL;
	BOOL isCompressed = FALSE;//标记是否被压缩

	while (*curLabelLoc)//每次循环处理一个标签或pointer,最后一个标签 值为0无法处理到
	{
		//通过位与来判断是否是压缩的信息
		if (((*curLabelLoc) & 0xC0) == 0xC0)//是压缩的信息pointer
		{
			if (isCompressed == FALSE)//是第一次跳转,可能有多次跳转的情况
			{
				isCompressed = TRUE;
				firstJumpLoc = (UINT16*)curLabelLoc;
			}
			
			pointer = (UINT16*)curLabelLoc;
			UINT16 offset = ntohs(*pointer) & 0x3FFF;//压缩的信息相对于头部的偏移量

			curLabelLoc = headerStartLoc + offset;//跳转到偏移量所指向地址
		}
		else//是普通的label，格式：标签长度+标签内容
		{
			int labelLen = *curLabelLoc;
			curLabelLoc++;//指向标签内容的第一个字节
			domainName[nameLen++] = labelLen;

			int i;
			for (i = 0; i < labelLen; i++)
			{
				domainName[nameLen++] = *curLabelLoc;
				curLabelLoc++;//指向下一个字节
			}
		}
		if (curLabelLoc == NULL)
			break;
	}
	//处理最后的0标签
	domainName[nameLen++] = '\0';

	//将转换得到的域名存到结构体中
	packetResponse->name = NULL;
	packetResponse->name = (char*)malloc(sizeof(char) * nameLen);
	if (packetResponse->name != NULL)
	{
		strcpy(packetResponse->name, domainName);
	}
	else;

	//更新当前处理的RR的位置
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

	//处理 type, rclass, ttl, rdLength
	packetResponse->type = ntohs(*curHandleLoc);
	packetResponse->rclass = ntohs(*(++curHandleLoc));
	packetResponse->ttl = (UINT32)ntohs(*((UINT32*)(++curHandleLoc)));
	curHandleLoc += 2;
	packetResponse->rdLength = ntohs(*curHandleLoc);
	curHandleLoc++;

	//处理rData
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

char* GetHeaderString(DNSHeader* header)	//dns头结构体转换为dns头字符
{
	char* headerString = NULL;
	headerString = (char*)malloc(sizeof(char) * (1 + DNS_HEADER_LEN));//分配空间
	if (headerString != NULL)
	{
		UINT16* curHandleLoc = (UINT16*)headerString;

		//转换id
		*(curHandleLoc++) = htons(header->id);

		//转换flag,用位或拼接出完整的flag
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

		//转换qdCount, anCount, nsCount, arCount
		*(curHandleLoc++) = htons(header->qdCount);
		*(curHandleLoc++) = htons(header->anCount);
		*(curHandleLoc++) = htons(header->nsCount);
		*(curHandleLoc) = htons(header->arCount);

		headerString[DNS_HEADER_LEN] = '\0';//给字符串加个终止符
	}
	else
		;

	return headerString;
}

char* GetQueryString(QUESTION* query)//dns请求段结构体转换为dns请求段字符
{
	int nameLen = strlen(query->qName) + 1;//+1是包含了终止符'\0'

	char* queryString = NULL;
	queryString = (char*)malloc(sizeof(char) * (nameLen + 5));//分配的空间大小为qName+qType(2)+qClass(2)+'\0'(1)
	if (queryString != NULL)
	{
		//转换qName
		strcpy(queryString, query->qName);//有个终止符

		//转换qType, qClass
		UINT16* curHandleLoc = (UINT16*)&queryString[nameLen];
		*curHandleLoc = htons(query->qType);
		*(++curHandleLoc) = htons(query->qClass);

		queryString[nameLen + 4] = '\0';//给字符串加个终止符
	}
	else
		;

	return queryString;
}

char* GetRRString(RR* response)	//dns回应段结构体转换为dns回应段字符
{
	int nameLen = strlen(response->name) + 1;//包含终止符的域名长度
	int totalRRLen = nameLen + 10 + (int)response->rdLength + 1;//10=type(2)+rdLength(2)+rclass(2)+ttl(4)

	char* responseString = NULL;
	responseString = (char*)malloc(sizeof(char) * totalRRLen);
	if (responseString != NULL)
	{
		//转换name
		strcpy(responseString, response->name);//有\0

		//转换type, rclass, ttl, rdLength
		UINT16* curHandleLoc = (UINT16*)&responseString[nameLen];
		*curHandleLoc = htons(response->type);
		curHandleLoc++;
		*curHandleLoc = htons(response->rclass);
		curHandleLoc++;
		*((UINT32*)curHandleLoc) = htons(response->ttl);
		curHandleLoc += 2;
		*curHandleLoc = htons(response->rdLength);
		curHandleLoc++;

		//转换rData
		memcpy((char*)curHandleLoc, response->rData, (size_t)response->rdLength);

		responseString[totalRRLen - 1] = '\0';
	}
	else
		;

	return responseString;
}

DNSPacket* MakeDNSPacket(char* recvString)//把dns字符串变成dns包结构体用以发送
{
	DNSPacket* newPacket = NULL;
	newPacket = (DNSPacket*)malloc(sizeof(DNSPacket));//先分配空间
	if (newPacket != NULL)//若空间分配成功
	{
		newPacket->queries = NULL;
		newPacket->answers = NULL;
		newPacket->authority = NULL;
		newPacket->additional = NULL;

		char* curStartLoc = recvString;//当前处理区域的首地址
		char* nextStartLoc = NULL;//下一个要处理的区域的首地址

		//先处理header区域，从字符串中转换出header结构
		newPacket->header = GetHeaderStruct(curStartLoc, &nextStartLoc);
		curStartLoc = nextStartLoc;//更新当前处理区域的首地址

		if (newPacket->header != NULL)//返回值不为空即为转换成功
		{
			UINT16 i;//for循环计数
			UINT16 size;//要某区域要分配的空间大小

			//处理查询问题区域，从字符串中转换出QUESTION结构
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

			//处理回答问题区域，从字符串中转换出RR结构
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

			//处理权威名称服务器区域，从字符串中转换出RR结构
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

			//处理附加信息区域，从字符串中转换出RR结构
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

char* GetDNSPacketString(DNSPacket* packet, int* len)//把dns包结构体变成字符串用以发送
{
	int queryLen = 0;
	int responseLen = 0;
	int totalLen = 0;

	char* headerString = GetHeaderString(packet->header);//要不要判空？？？
	char** queryString = NULL;
	char** reponseString = NULL;

	UINT16 i;
	UINT16 size;
	//转换query部分
	size = packet->header->qdCount;
	if (size > 0)
	{
		queryString = (char**)malloc(sizeof(char*) * size);
		for (i = 0; i < size; i++)
		{
			queryString[i] = GetQueryString(&packet->queries[i]);
			queryLen += strlen(queryString[i]) + 5;//strlen(queryString[i])算的只是qName的部分（因为有'\0'）,5= 2+2+1(\0)
			//queryLen += strlen(packet->queries[i].qName) + 5;
		}
	}

	size = packet->header->anCount + packet->header->nsCount + packet->header->arCount;//rr部分的个数总数
	int* eachRRLen = (int*)malloc(sizeof(int) * size);
	if (size > 0)
	{
		reponseString = (char**)malloc(sizeof(char*) * size);
		int count = 0;

		for (i = 0; i < packet->header->anCount && count < size; i++)//转换answers部分
		{
			reponseString[count] = GetRRString(&packet->answers[i]);
			eachRRLen[count] = strlen(packet->answers[i].name) + 11 + (int)packet->answers[i].rdLength;//11=type(2)+rdLength(2)+rclass(2)+ttl(4)+\0
			responseLen += eachRRLen[count];
			count++;
		}
		for (i = 0; i < packet->header->nsCount && count < size; i++)//转换authority部分
		{
			reponseString[count] = GetRRString(&packet->authority[i]);
			eachRRLen[count] = strlen(packet->authority[i].name) + 11 + (int)packet->authority[i].rdLength;//11=type(2)+rdLength(2)+rclass(2)+ttl(4)+\0
			responseLen += eachRRLen[count];
			count++;
		}
		for (i = 0; i < packet->header->arCount && count < size; i++)//转换additional部分
		{
			reponseString[count] = GetRRString(&packet->additional[i]);
			eachRRLen[count] = strlen(packet->additional[i].name) + 11 + (int)packet->additional[i].rdLength;//11=type(2)+rdLength(2)+rclass(2)+ttl(4)+\0
			responseLen += eachRRLen[count];
			count++;
		}
	}

	totalLen = DNS_HEADER_LEN + queryLen + responseLen;
	char* packetString = (char*)malloc(sizeof(char) * (totalLen + 1));

	//拼接各个部分变成一个完整的包字符串
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

char* GetNormalDomainName(char* DNSDomainName)//把dns形式的域名转换成常规形式的域名
{
	char tempResult[256];
	char* curHandleLoc = DNSDomainName;
	int offset = 0;
	int labelLen = *curHandleLoc;

	//if ((DNSDomainName[0] >= 'A' && DNSDomainName[0] <= 'Z')
	//	|| (DNSDomainName[0] >= 'a' && DNSDomainName[0] <= 'z')
	//	|| (DNSDomainName[0] >= '0' && DNSDomainName[0] <= '9'))
	//{
	//	//本身是常规形式域名就直接返回
	//	return DNSDomainName;
	//}

	while (labelLen)
	{
		curHandleLoc++;//指向标签内容的第一个字符
		int i = 0;
		for (i = 0; i < labelLen; i++)
		{
			tempResult[offset] = *curHandleLoc;
			offset++;//偏移量指向下一个位置
			curHandleLoc++;//当前处理指向下一个字符
		}
		labelLen = *curHandleLoc;//处理完一个标签，更新标签长度为下一个标签的长度

		if (labelLen != 0)//若下一个标签长度不为0,即域名还未读入结束，给域名增加分隔符‘.’
		{
			tempResult[offset] = '.';
			offset++;
		}
		else//否则即为读入结束，给字符串增加终止符'\0'
		{
			tempResult[offset] = '\0';
		}
	}

	int len = strlen(tempResult);
	char* normalDomainName = (char*)malloc(sizeof(char) * (len + 1));
	strcpy(normalDomainName, tempResult);

	return normalDomainName;
}

char* GetDNSDomainName(char* normalDomainName)//把常规形式的域名转换成dns形式的域名
{
	char tempResult[256];
	char* curHandleLoc = normalDomainName;
	UINT8 labelStartLoc = 0;//标签开始的地方（记录标签长度的那个字节的位置）

	while (*curHandleLoc != '\0')
	{
		UINT8 labelLen = 0;
		while ((*curHandleLoc != '\0') && (*curHandleLoc != '.'))//没有读到'.'代表一个标签还没有读完
		{
			labelLen++;
			tempResult[labelStartLoc + labelLen] = *curHandleLoc;
			curHandleLoc++;
		}
		tempResult[labelStartLoc] = labelLen;
		labelStartLoc += labelLen + 1;//更新标签开始的地方
	}
	tempResult[labelStartLoc] = '\0';

	int len = strlen(tempResult);
	char* DNSDomainName = (char*)malloc(sizeof(char) * (len + 1));
	strcpy(DNSDomainName, tempResult);

	return DNSDomainName;
}