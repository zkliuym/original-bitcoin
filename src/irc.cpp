// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// irc.cpp — Bitcoin v0.1.3 基于 IRC 的节点发现实现
//=============================================================================
//
// 【本文件功能】
//   将本机 IPv4/端口编码进 IRC 昵称，连接 Freenode 的 #bitcoin 频道，
//   从 WHO/JOIN 消息提取其他节点昵称并解码为 CAddress。
//
// 【在整个系统中的作用】
//   这是早期客户端的冷启动引导机制：发现的地址写入 CAddrDB/mapAddresses，
//   随后由 net.cpp 的 ThreadOpenConnections 选择并建立真正的 P2P TCP 连接。
//   IRC 只交换地址线索，不传输交易、区块或钱包数据。
//
// 【阅读提示】
//   先看 EncodeAddress/DecodeAddress 理解昵称格式，再看 RecvLineIRC 的
//   PING/PONG 保活，最后看 ThreadIRCSeed 的连接、注册、WHO 与重连状态机。
//
//=============================================================================

#include "headers.h"




#pragma pack(1)
// IRC 昵称载荷的紧凑二进制布局；字段保持 socket 网络字节序。
struct ircaddr
{
    int ip;
    short port;
};

// 把 IPv4+端口做 Base58Check 编码，并加前缀 'u' 形成可识别昵称。
string EncodeAddress(const CAddress& addr)
{
    struct ircaddr tmp;
    tmp.ip    = addr.ip;
    tmp.port  = addr.port;

    vector<unsigned char> vch(UBEGIN(tmp), UEND(tmp));
    return string("u") + EncodeBase58Check(vch);
}

// 校验并还原 'u'+Base58Check 昵称；失败时不产生可用地址。
bool DecodeAddress(string str, CAddress& addr)
{
    vector<unsigned char> vch;
    if (!DecodeBase58Check(str.substr(1), vch))
        return false;

    struct ircaddr tmp;
    if (vch.size() != sizeof(tmp))
        return false;
    memcpy(&tmp, &vch[0], sizeof(tmp));

    addr  = CAddress(tmp.ip, tmp.port);
    return true;
}






// 确保整段 IRC 命令被写入 socket；PONG 不打印以减少日志噪声。
static bool Send(SOCKET hSocket, const char* pszSend)
{
    if (strstr(pszSend, "PONG") != pszSend)
        printf("SENDING: %s\n", pszSend);
    const char* psz = pszSend;
    const char* pszEnd = psz + strlen(psz);
    while (psz < pszEnd)
    {
        int ret = send(hSocket, psz, pszEnd - psz, 0);
        if (ret < 0)
            return false;
        psz += ret;
    }
    return true;
}

// 逐字节读取 CRLF 文本行；'\r' 结束，'\n' 忽略。
// socket 关闭时仍返回已积累的最后一行。
bool RecvLine(SOCKET hSocket, string& strLine)
{
    strLine = "";
    loop
    {
        char c;
        int nBytes = recv(hSocket, &c, 1, 0);
        if (nBytes > 0)
        {
            if (c == '\n')
                continue;
            if (c == '\r')
                return true;
            strLine += c;
        }
        else if (nBytes <= 0)
        {
            if (!strLine.empty())
                return true;
            // socket closed
            printf("IRC socket closed\n");
            return false;
        }
        else
        {
            // socket error
            int nErr = WSAGetLastError();
            if (nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
            {
                printf("IRC recv failed: %d\n", nErr);
                return false;
            }
        }
    }
}

// IRC 专用行读取器：自动把服务端 PING 改为 PONG 后继续等待业务行。
bool RecvLineIRC(SOCKET hSocket, string& strLine)
{
    loop
    {
        bool fRet = RecvLine(hSocket, strLine);
        if (fRet)
        {
            if (fShutdown)
                return false;
            vector<string> vWords;
            ParseString(strLine, ' ', vWords);
            if (vWords[0] == "PING")
            {
                strLine[1] = 'O';
                strLine += '\r';
                Send(hSocket, strLine.c_str());
                continue;
            }
        }
        return fRet;
    }
}

// 持续读取并打印 IRC 行，直到出现任一指定标记。
bool RecvUntil(SOCKET hSocket, const char* psz1, const char* psz2=NULL, const char* psz3=NULL)
{
    loop
    {
        string strLine;
        if (!RecvLineIRC(hSocket, strLine))
            return false;
        printf("IRC %s\n", strLine.c_str());
        if (psz1 && strLine.find(psz1) != -1)
            return true;
        if (psz2 && strLine.find(psz2) != -1)
            return true;
        if (psz3 && strLine.find(psz3) != -1)
            return true;
    }
}

// 可被 fShutdown 中断的重连等待，避免退出时长时间阻塞。
bool Wait(int nSeconds)
{
    if (fShutdown)
        return false;
    printf("Waiting %d seconds to reconnect to IRC\n", nSeconds);
    for (int i = 0; i < nSeconds; i++)
    {
        if (fShutdown)
            return false;
        Sleep(1000);
    }
    return true;
}



// IRC seed 主线程：
//   连接 Freenode → 注册编码昵称 → 加入 #bitcoin → WHO/JOIN 收集地址；
//   断线后递增等待时间重试，直至全局关闭。
void ThreadIRCSeed(void* parg)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    int nErrorWait = 30;
    int nRetryWait = 10;


    while (!fShutdown)
    {
        // 每轮重新解析服务器，允许 DNS 返回可用的不同入口。
        struct hostent* phostent = gethostbyname("chat.freenode.net");
        CAddress addrConnect(*(u_long*)phostent->h_addr_list[0], htons(6667));

        SOCKET hSocket;
        if (!ConnectSocket(addrConnect, hSocket))
        {
            printf("IRC connect failed\n");
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }

        if (!RecvUntil(hSocket, "Found your hostname", "using your IP address instead", "Couldn't look up your hostname"))
        {
            closesocket(hSocket);
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }

        // 可路由节点用地址昵称公开自己；内网节点用随机昵称避免发布无效地址。
        string strMyName = EncodeAddress(addrLocalHost);

        if (!addrLocalHost.IsRoutable())
            strMyName = strprintf("x%u", GetRand(1000000000));


        Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
        Send(hSocket, strprintf("USER %s 8 * : %s\r", strMyName.c_str(), strMyName.c_str()).c_str());

        if (!RecvUntil(hSocket, " 004 "))
        {
            closesocket(hSocket);
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }
        Sleep(500);

        // JOIN 接收后续加入事件，WHO 获取当前已经在线的完整成员列表。
        Send(hSocket, "JOIN #bitcoin\r");
        Send(hSocket, "WHO #bitcoin\r");

        string strLine;
        while (!fShutdown && RecvLineIRC(hSocket, strLine))
        {
            if (strLine.empty() || strLine.size() > 900 || strLine[0] != ':')
                continue;
            printf("IRC %s\n", strLine.c_str());

            vector<string> vWords;
            ParseString(strLine, ' ', vWords);
            if (vWords.size() < 2)
                continue;

            char pszName[10000];
            pszName[0] = '\0';

            // 数字回复 352 是 WHO 条目；字段 7 为昵称。
            if (vWords[1] == "352" && vWords.size() >= 8)
            {
                // index 7 is limited to 16 characters
                // could get full length name at index 10, but would be different from join messages
                strcpy(pszName, vWords[7].c_str());
                printf("GOT WHO: [%s]  ", pszName);
            }

            // JOIN 实时补充在线后新进入频道的节点。
            if (vWords[1] == "JOIN" && vWords[0].size() > 1)
            {
                // :username!username@50000007.F000000B.90000002.IP JOIN :#channelname
                strcpy(pszName, vWords[0].c_str() + 1);
                if (strchr(pszName, '!'))
                    *strchr(pszName, '!') = '\0';
                printf("GOT JOIN: [%s]  ", pszName);
            }

            // 仅解析本协议约定的 'u' 前缀昵称，忽略普通 IRC 用户。
            if (pszName[0] == 'u')
            {
                CAddress addr;
                if (DecodeAddress(pszName, addr))
                {
                    CAddrDB addrdb;
                    if (AddAddress(addrdb, addr))
                        printf("new  ");
                    addr.print();
                }
                else
                {
                    printf("decode failed\n");
                }
            }

        }
        closesocket(hSocket);

        if (!Wait(nRetryWait += 10))
            return;
    }
}










#ifdef TEST
// 独立测试入口：仅用于手工验证 IRC seed 流程。
int main(int argc, char *argv[])
{
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2,2), &wsadata) != NO_ERROR)
    {
        printf("Error at WSAStartup()\n");
        return false;
    }

    ThreadIRCSeed(NULL);

    WSACleanup();
    return 0;
}
#endif
