#include <iostream>
#include"mytracert.h"

int main(int argc, char* argv[])
{

	WSADATA wsData;
	if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0)
	{
		cout << "WSAstartup failed!";
		return 1;
	}
	if (argc != 2)
	{
		
		cout << "请输入IP地址或主机名：\n";
		char temp[64];
		cin >> temp;
		argv[1] = temp;
	}
	//解析目的地址
	unsigned long desIP = inet_addr(argv[1]);//点分十进制IP转为长整型

	if (desIP == INADDR_NONE)
	{
		//失败说明按照域名解析
		hostent* pHostent = gethostbyname(argv[1]);
		if (pHostent)
		{
			desIP = (*(in_addr*)pHostent->h_addr).s_addr;

			cout << "\nTracing route to " << argv[1]
				<< " [" << inet_ntoa(*(in_addr*)(&desIP)) << "]"
				<< " with a maximum of " << DEF_MAX_HOP << " hops.\n" << endl;
		}
		else //解析主机名失败
		{
			cerr << "\nCould not resolve the host name " << argv[1] << '\n'
				<< "error code: " << WSAGetLastError() << endl;
			WSACleanup();
			return -1;
		}
	}
	else
	{
		//命令输入IP地址，输出屏幕信息
		cout << "\nTracing route to " << argv[1]
			<< " with a maximum of " << DEF_MAX_HOP << " hops.\n" << endl;
	}

	//填充目的Socket地址
	sockaddr_in destSockAddr;
	ZeroMemory(&destSockAddr, sizeof(sockaddr_in));//初始化内存为0
	destSockAddr.sin_family = AF_INET;
	ULONG t1 = (desIP);
	destSockAddr.sin_addr.s_addr = t1;

	//使用ICMP协议创建Raw Socket
	SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (sockRaw == INVALID_SOCKET)//需要管理员权限
	{
		cerr << "\nFailed to create a raw socket\n"
			<< "error code: " << WSAGetLastError() << endl;
		WSACleanup();
		return -1;
	}
	//超时时间
	int iTimeout = DEF_ICMP_TIMEOUT;
	//设置接收和发送超时时间
	if (setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeout, sizeof(iTimeout)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to set recv timeout\n"
			<< "error code: " << WSAGetLastError() << "\n 请确认具有管理员权限" << endl;
		closesocket(sockRaw);
		WSACleanup();
		return -1;
	}
	if (setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&iTimeout, sizeof(iTimeout)) == SOCKET_ERROR)
	{
		cerr << "\nFailed to set send timeout\n"
			<< "error code: " << WSAGetLastError() 
			<< "\n 请确认具有管理员权限" << endl;
		closesocket(sockRaw);
		WSACleanup();
		return -1;
	}
	
	//创建ICMP包发送缓冲区
	char IcmpSendBuf[sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE];
	ZeroMemory(IcmpSendBuf, sizeof(IcmpSendBuf));
	//创建ICMP包接收缓冲区
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];
	ZeroMemory(IcmpRecvBuf, sizeof(IcmpRecvBuf));
	//cout << "缓冲区创建成功";

	//填充待发送的ICMP包
	ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	pIcmpHeader->type = ICMP_ECHO_REQUEST;
	pIcmpHeader->code = 0;
	pIcmpHeader->id = (USHORT)GetCurrentProcessId();
	memset(IcmpSendBuf + sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);

	USHORT usSeqNo = 0;
	int iTTL = 1;
	BOOL bReachDestHost = FALSE;
	int iMaxHop = DEF_MAX_HOP;
	DECODE_RESULT stDecodeResult;
	while (!bReachDestHost && iMaxHop--)
	{
		//设置IP数据报头的ttl字段n
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&iTTL, sizeof(iTTL));
		//输出当前跳站数作为路由信息序号
		cout << setw(3) << iTTL << flush;
		//填充ICMP数据报剩余字段
		((ICMP_HEADER*)IcmpSendBuf)->cksum = 0;
		//USHORT temp = (usSeqNo++);
		//htons(temp);
		((ICMP_HEADER*)IcmpSendBuf)->seq = htons(usSeqNo++);
		((ICMP_HEADER*)IcmpSendBuf)->cksum = GenerateChecksum((USHORT*)IcmpSendBuf, sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE);
		//记录序列号和当前时间
		stDecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;
		stDecodeResult.dwRoundTripTime = GetTickCount64();
		//发送ICMP的EchoRequest数据报
		UINT tesb = sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0,
			(sockaddr*)&destSockAddr, sizeof(destSockAddr));
		//if (sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0,
		//	(sockaddr*)&destSockAddr, sizeof(destSockAddr)) == SOCKET_ERROR)
		//{
		//	//如果目的主机不可达则直接退出
		//	if (WSAGetLastError() == WSAEHOSTUNREACH)
		//		cout << '\t' << "Destination host unreachable.\n"
		//		<< "\nTrace complete.\n" << endl;
		//	closesocket(sockRaw);
		//	WSACleanup();
		//	return 0;
		//}
		
		//接收处理
		sockaddr_in from; //对端Socket地址
		int iFromLen = sizeof(from);//地址结构大小
		int iReadDataLen = 0;//接收数据长度
		while (true)
		{
			//等待数据到达
			//cout << sizeof(IcmpRecvBuf) << endl;
			iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE,
									0, (sockaddr*)&from, &iFromLen);
			IP_HEADER* pIpHdr = (IP_HEADER*)IcmpRecvBuf;
			int error = WSAGetLastError();	
			if (iReadDataLen != SOCKET_ERROR)
			{
				//解码得到的数据包，如果解码正确则跳出接收循环发送下一个包
				if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, stDecodeResult))
				{
					if (stDecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
						bReachDestHost = TRUE;

					cout << '\t' << inet_ntoa(stDecodeResult.dwIPaddr) << endl;
					break;
				}
			}
			else if (error == WSAETIMEDOUT) //接收超时，打印星号
			{
				cout << setw(9) << '*' << '\t' << "Request timed out." << endl;
				cout << "Error Number：" << error << endl;

				break;
			}
			else
			{
				cerr << "\nFailed to call recvfrom\n"
					<< "error code: " << WSAGetLastError() << endl;
				closesocket(sockRaw);
				WSACleanup();
				return -1;
			}
		}
		iTTL++;
	}

}
USHORT GenerateChecksum(USHORT* pBuf, int iSize)
{
	unsigned long cksum = 0;
	while (iSize > 1)
	{
		cksum += *pBuf++;
		iSize -= sizeof(USHORT);
	}
	if (iSize) {
		cksum += *(UCHAR*)pBuf;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (USHORT)(~cksum);
}

int getIpHdrLen(char ver_hdrLen) {
	return ((int)(ver_hdrLen & 0x0f)) * 4;
}
//解码得到的数据报
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& stDecodeResult)
{
	IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	int iIpHdrLen = pIpHdr->hdr_len * 4;//获取头部长度
	ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)(pBuf + iIpHdrLen);
	USHORT usID, usSquNo;
	if (pIcmpHeader->type == my_ICMP_ECHO_REPLY) //ICMP 回显报文
	{
		usID = pIcmpHeader->id;
		usSquNo = pIcmpHeader->seq;
	}
	else if (pIcmpHeader->type == ICMP_TIMEOUT)//ICMP超时差错报文
	{
		char* pInnerIpHdr = pBuf + iIpHdrLen + sizeof(ICMP_HEADER);		//载荷中的IP头
		int iInnerIPHdrLen = ((IP_HEADER*)pInnerIpHdr)->hdr_len * 4;//载荷中的IP头长
		ICMP_HEADER* pInnerIcmpHdr = (ICMP_HEADER*)(pInnerIpHdr + iInnerIPHdrLen);//载荷中的ICMP头
		usID = pInnerIcmpHdr->id;
		usSquNo = pInnerIcmpHdr->seq;
	}
	else
	{
		return FALSE;
	}

	if (usID != (USHORT)GetCurrentProcessId() || usSquNo != stDecodeResult.usSeqNo)
	{
		return FALSE;
	}
	if (pIcmpHeader->type == my_ICMP_ECHO_REPLY ||
		pIcmpHeader->type == ICMP_TIMEOUT)
	{
		//返回解码结果
		stDecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
		stDecodeResult.dwRoundTripTime = GetTickCount64() - stDecodeResult.dwRoundTripTime;

		//打印屏幕信息
		if (stDecodeResult.dwRoundTripTime)
			cout << setw(6) << stDecodeResult.dwRoundTripTime << " ms" << flush;
		else
			cout << setw(6) << "<1" << " ms" << flush;

		return TRUE;
	}
	return FALSE;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
