// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// net.h — Bitcoin v0.1.3 P2P 网络层的数据结构与接口
//=============================================================================
//
// 【本文件功能】
//   定义节点通信所需的消息头、网络地址、库存标识、请求回调和连接对象，
//   并提供消息组包、库存中继、发布/订阅以及网络线程入口的公共接口。
//
// 【在整个系统中的作用】
//   1. CMessageHeader 规定 P2P 数据包边界与命令名。
//   2. CAddress / CInv 表示可连接节点和待传播对象的“类型+哈希”。
//   3. CNode 保存单条 TCP 连接的缓冲、握手状态、去重集合和请求队列。
//   4. net.cpp 驱动 socket 与线程；main.cpp 解析和生成具体协议消息。
//
// 【阅读提示】
//   建议按 CMessageHeader → CAddress → CInv → CNode → RelayMessage 阅读；
//   PushMessage 只负责封包，实际发送由 ThreadSocketHandler 异步完成；
//   ip 与 port 保持网络字节序，显示和数值比较时再做 ntoh* 转换。
//
//=============================================================================

// 网络层核心类型的前置声明。
class CMessageHeader;
class CAddress;
class CInv;
class CRequestTracker;
class CNode;



// 主网默认 TCP 端口（网络字节序）与早期市场消息的无条件扩散跳数。
static const unsigned short DEFAULT_PORT = htons(8333);
static const unsigned int PUBLISH_HOPS = 5;
enum
{
    // 节点能够提供完整区块链网络服务。
    NODE_NETWORK = (1 << 0),
};






bool ConnectSocket(const CAddress& addrConnect, SOCKET& hSocketRet); // 建立直连或 SOCKS4 代理连接
bool GetMyExternalIP(unsigned int& ipRet);                           // 通过外部 HTTP 服务探测公网 IP
bool AddAddress(CAddrDB& addrdb, const CAddress& addr);              // 地址簿去重并持久化
CNode* FindNode(unsigned int ip);                                    // 按 IP 查找现有连接
CNode* ConnectNode(CAddress addrConnect, int64 nTimeout=0);          // 复用或创建出站连接
// 删除指定对象关联的异步请求，防止对象销毁后回调。
void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1);
bool AnySubscribed(unsigned int nChannel);                              // 全局查询频道订阅状态
void ThreadBitcoinMiner(void* parg);                                 // 挖矿线程入口
bool StartNode(string& strError=REF(string()));                      // 初始化网络并启动工作线程
bool StopNode();                                                     // 通知线程退出并清理 Winsock
void CheckForShutdown(int n);                                        // 在线程安全点响应关闭









//
// Message header — 每条线上消息固定 20 字节的包头
//  (4) message start
//  (12) command
//  (4) size

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
// 主网魔数：用于从 TCP 字节流中识别消息边界。
static const char pchMessageStart[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };

// CMessageHeader：P2P 帧头，不含 payload。
// 接收端先验证魔数、命令字符和长度，再由 ProcessMessages 分派消息体。
class CMessageHeader
{
public:
    enum { COMMAND_SIZE=12 };                         // 命令名固定槽长度
    char pchMessageStart[sizeof(::pchMessageStart)]; // 网络魔数
    char pchCommand[COMMAND_SIZE];                   // NUL 填充的 ASCII 命令
    unsigned int nMessageSize;                       // payload 字节数

    CMessageHeader()
    {
        memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
        memset(pchCommand, 0, sizeof(pchCommand));
        pchCommand[1] = 1;
        nMessageSize = -1;
    }

    CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn)
    {
        memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
        strncpy(pchCommand, pszCommand, COMMAND_SIZE);
        nMessageSize = nMessageSizeIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
    )

    // 将定长命令槽转换为普通字符串。
    string GetCommand()
    {
        if (pchCommand[COMMAND_SIZE-1] == 0)
            return string(pchCommand, pchCommand + strlen(pchCommand));
        else
            return string(pchCommand, pchCommand + COMMAND_SIZE);
    }

    // 校验魔数、命令格式及 256 MiB 的消息长度上限。
    bool IsValid()
    {
        // Check start string
        if (memcmp(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart)) != 0)
            return false;

        // Check the command string for errors
        for (char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
        {
            if (*p1 == 0)
            {
                // Must be all zeros after the first zero
                for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                    if (*p1 != 0)
                        return false;
            }
            else if (*p1 < ' ' || *p1 > 0x7E)
                return false;
        }

        // Message size
        if (nMessageSize > 0x10000000)
        {
            printf("CMessageHeader::IsValid() : nMessageSize too large %u\n", nMessageSize);
            return false;
        }

        return true;
    }
};






// IPv4-mapped IPv6 的 12 字节前缀，使地址在线格式固定预留 16 字节。
static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

// CAddress：节点网络地址及其服务能力。
// 网络消息传 services + 16 字节 IP + port；磁盘地址簿还保存版本和时间。
class CAddress
{
public:
    uint64 nServices;              // 对端能力位，如 NODE_NETWORK
    unsigned char pchReserved[12]; // IPv4 映射前缀/未来 IPv6 预留
    unsigned int ip;               // IPv4，网络字节序
    unsigned short port;           // TCP 端口，网络字节序

    // 仅磁盘序列化：地址最后更新时间。
    unsigned int nTime;

    // 仅内存：最近连接失败时间，用于退避选址。
    unsigned int nLastFailed;

    // 构造函数统一保持 IP/端口为网络字节序，并初始化地址时间。
    CAddress()
    {
        nServices = 0;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = 0;
        port = DEFAULT_PORT;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    CAddress(unsigned int ipIn, unsigned short portIn=DEFAULT_PORT, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = ipIn;
        port = portIn;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    explicit CAddress(const struct sockaddr_in& sockaddr, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = sockaddr.sin_addr.s_addr;
        port = sockaddr.sin_port;
        nTime = GetAdjustedTime();
        nLastFailed = 0;
    }

    explicit CAddress(const char* pszIn, uint64 nServicesIn=0)
    {
        nServices = nServicesIn;
        memcpy(pchReserved, pchIPv4, sizeof(pchReserved));
        ip = 0;
        port = DEFAULT_PORT;
        nTime = GetAdjustedTime();
        nLastFailed = 0;

        char psz[100];
        if (strlen(pszIn) > ARRAYLEN(psz)-1)
            return;
        strcpy(psz, pszIn);
        unsigned int a, b, c, d, e;
        if (sscanf(psz, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &e) < 4)
            return;
        char* pszPort = strchr(psz, ':');
        if (pszPort)
        {
            *pszPort++ = '\0';
            port = htons(atoi(pszPort));
        }
        ip = inet_addr(psz);
    }

    // SER_DISK 比线上格式额外写入版本和时间；nLastFailed 永不序列化。
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
        {
            READWRITE(nVersion);
            READWRITE(nTime);
        }
        READWRITE(nServices);
        READWRITE(FLATDATA(pchReserved));
        READWRITE(ip);
        READWRITE(port);
    )

    friend inline bool operator==(const CAddress& a, const CAddress& b)
    {
        return (memcmp(a.pchReserved, b.pchReserved, sizeof(a.pchReserved)) == 0 &&
                a.ip   == b.ip &&
                a.port == b.port);
    }

    friend inline bool operator<(const CAddress& a, const CAddress& b)
    {
        int ret = memcmp(a.pchReserved, b.pchReserved, sizeof(a.pchReserved));
        if (ret < 0)
            return true;
        else if (ret == 0)
        {
            if (ntohl(a.ip) < ntohl(b.ip))
                return true;
            else if (a.ip == b.ip)
                return ntohs(a.port) < ntohs(b.port);
        }
        return false;
    }

    // 生成 reserved+ip+port 的稳定键，供 mapAddresses 去重和排序。
    vector<unsigned char> GetKey() const
    {
        CDataStream ss;
        ss.reserve(18);
        ss << FLATDATA(pchReserved) << ip << port;

        #if defined(_MSC_VER) && _MSC_VER < 1300
        return vector<unsigned char>((unsigned char*)&ss.begin()[0], (unsigned char*)&ss.end()[0]);
        #else
        return vector<unsigned char>(ss.begin(), ss.end());
        #endif
    }

    // 转换为 Winsock 可直接用于 connect/bind 的 sockaddr_in。
    struct sockaddr_in GetSockAddr() const
    {
        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = ip;
        sockaddr.sin_port = port;
        return sockaddr;
    }

    // 当前地址是否使用标准 IPv4 映射前缀。
    bool IsIPv4() const
    {
        return (memcmp(pchReserved, pchIPv4, sizeof(pchIPv4)) == 0);
    }

    // 排除私网、回环和 0/8 等不可公开路由地址。
    bool IsRoutable() const
    {
        return !(GetByte(3) == 10 || (GetByte(3) == 192 && GetByte(2) == 168) || GetByte(3) == 127 || GetByte(3) == 0);
    }

    unsigned char GetByte(int n) const
    {
        return ((unsigned char*)&ip)[3-n];
    }

    string ToStringIPPort() const
    {
        return strprintf("%u.%u.%u.%u:%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0), ntohs(port));
    }

    string ToStringIP() const
    {
        return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    }

    string ToString() const
    {
        return strprintf("%u.%u.%u.%u:%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0), ntohs(port));
        //return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    }

    void print() const
    {
        printf("CAddress(%s)\n", ToString().c_str());
    }
};







enum
{
    // inv/getdata 对象类型；后 3 项属于 v0.1.3 的早期市场功能。
    MSG_TX = 1,
    MSG_BLOCK,
    MSG_REVIEW,
    MSG_PRODUCT,
    MSG_TABLE,
};

// CInv 类型编号到 P2P 命令名的映射。
static const char* ppszTypeName[] =
{
    "ERROR",
    "tx",
    "block",
    "review",
    "product",
    "table",
};

// CInv（inventory vector）：用“对象类型 + 256 位哈希”标识可中继对象。
// inv 只通告标识；接收方若缺少对象，再用 getdata 请求完整内容。
class CInv
{
public:
    int type;     // MSG_TX、MSG_BLOCK 等
    uint256 hash; // 对象内容哈希

    CInv()
    {
        type = 0;
        hash = 0;
    }

    CInv(int typeIn, const uint256& hashIn)
    {
        type = typeIn;
        hash = hashIn;
    }

    CInv(const string& strType, const uint256& hashIn)
    {
        int i;
        for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
        {
            if (strType == ppszTypeName[i])
            {
                type = i;
                break;
            }
        }
        if (i == ARRAYLEN(ppszTypeName))
            throw std::out_of_range(strprintf("CInv::CInv(string, uint256) : unknown type '%s'", strType.c_str()));
        hash = hashIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(type);
        READWRITE(hash);
    )

    friend inline bool operator<(const CInv& a, const CInv& b)
    {
        return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
    }

    // 确认类型编号能安全索引 ppszTypeName。
    bool IsKnownType() const
    {
        return (type >= 1 && type < ARRAYLEN(ppszTypeName));
    }

    // 返回该库存类型对应的协议命令名。
    const char* GetCommand() const
    {
        if (!IsKnownType())
            throw std::out_of_range(strprintf("CInv::GetCommand() : type=% unknown type", type));
        return ppszTypeName[type];
    }

    string ToString() const
    {
        return strprintf("%s %s", GetCommand(), hash.ToString().substr(0,14).c_str());
    }

    void print() const
    {
        printf("CInv(%s)\n", ToString().c_str());
    }
};





// CRequestTracker：旧式异步请求/回复机制的回调记录。
// PushRequest 生成随机回复 ID，响应到达后据此调用回调。
class CRequestTracker
{
public:
    void (*fn)(void*, CDataStream&); // 回复到达时执行
    void* param1;                    // 调用方上下文

    explicit CRequestTracker(void (*fnIn)(void*, CDataStream&)=NULL, void* param1In=NULL)
    {
        fn = fnIn;
        param1 = param1In;
    }

    bool IsNull()
    {
        return fn == NULL;
    }
};





// 网络子系统共享状态；访问容器时须持有紧邻声明的临界区。
extern bool fClient;                    // 是否为不提供完整服务的客户端
extern uint64 nLocalServices;           // 本节点对外声明的服务位
extern CAddress addrLocalHost;          // 本机对外通告地址
extern CNode* pnodeLocalHost;           // 保存本机订阅状态的伪节点
extern bool fShutdown;                  // 全局停止标志
extern array<bool, 10> vfThreadRunning; // 工作线程运行标志
extern vector<CNode*> vNodes;           // 当前活动连接
extern CCriticalSection cs_vNodes;
extern map<vector<unsigned char>, CAddress> mapAddresses; // 已知地址簿
extern CCriticalSection cs_mapAddresses;
extern map<CInv, CDataStream> mapRelay;             // 可响应 getdata 的消息缓存
extern deque<pair<int64, CInv> > vRelayExpiration;  // 中继缓存过期队列
extern CCriticalSection cs_mapRelay;
extern map<CInv, int64> mapAlreadyAskedFor;         // 请求重试节流时间
extern CAddress addrProxy;                          // 可选 SOCKS4 代理





// CNode：一条活动 P2P TCP 连接的完整运行时状态。
// socket 线程只搬运字节；消息线程负责协议解析与消息生成。
class CNode
{
public:
    // socket 与握手状态
    uint64 nServices;      // version 消息中获知的对端服务位
    SOCKET hSocket;        // 对端 TCP socket
    CDataStream vSend;     // 等待 socket 线程发送的消息字节
    CDataStream vRecv;     // 等待消息线程解析的接收字节
    CCriticalSection cs_vSend;
    CCriticalSection cs_vRecv;
    unsigned int nPushPos; // 正在组装的消息头位置；-1 表示无消息
    CAddress addr;         // 对端地址
    int nVersion;          // 握手协商后的协议版本
    bool fClient;          // 对端是否不提供 NODE_NETWORK
    bool fInbound;         // 是否为 accept 得到的入站连接
    bool fNetworkNode;     // 是否由自动出站线程维护
    bool fDisconnect;      // 请求 socket 线程断开
protected:
    int nRefCount;         // 跨线程生命周期引用计数
public:
    int64 nReleaseTime;    // 超时引用的最晚释放时刻
    map<uint256, CRequestTracker> mapRequests; // 回复 ID → 回调
    CCriticalSection cs_mapRequests;

    // 地址洪泛：待发地址及对端已知地址集合。
    vector<CAddress> vAddrToSend;
    set<CAddress> setAddrKnown;

    // 库存中继：已知集合去重，待发向量由 SendMessages 批量发出。
    set<CInv> setInventoryKnown;
    set<CInv> setInventoryKnown2;
    vector<CInv> vInventoryToSend;
    CCriticalSection cs_inventory;
    multimap<int64, CInv> mapAskFor; // 最早请求时刻 → 库存

    // 早期市场功能的频道订阅位图。
    vector<char> vfSubscribe;


    // 接管 socket、初始化协议状态，并立即排入 version 握手。
    CNode(SOCKET hSocketIn, CAddress addrIn, bool fInboundIn=false)
    {
        nServices = 0;
        hSocket = hSocketIn;
        vSend.SetType(SER_NETWORK);
        vRecv.SetType(SER_NETWORK);
        nPushPos = -1;
        addr = addrIn;
        nVersion = 0;
        fClient = false; // set by version message
        fInbound = fInboundIn;
        fNetworkNode = false;
        fDisconnect = false;
        nRefCount = 0;
        nReleaseTime = 0;
        vfSubscribe.assign(256, false);

        // 创建后立即排入 version 握手消息，并不在构造函数内直接 send。
        /// when NTP implemented, change to just nTime = GetAdjustedTime()
        int64 nTime = (fInbound ? GetAdjustedTime() : GetTime());
        PushMessage("version", VERSION, nLocalServices, nTime, addr);
    }

    ~CNode()
    {
        if (hSocket != INVALID_SOCKET)
            closesocket(hSocket);
    }

private:
    CNode(const CNode&);
    void operator=(const CNode&);
public:


    // 已要求断开或引用全部释放时，可进入断开流程。
    bool ReadyToDisconnect()
    {
        return fDisconnect || GetRefCount() <= 0;
    }

    // 显式引用与尚未到期的超时引用共同决定有效引用数。
    int GetRefCount()
    {
        return max(nRefCount, 0) + (GetTime() < nReleaseTime ? 1 : 0);
    }

    // 增加普通引用，或把超时保活期限向后延长。
    void AddRef(int64 nTimeout=0)
    {
        if (nTimeout != 0)
            nReleaseTime = max(nReleaseTime, GetTime() + nTimeout);
        else
            nRefCount++;
    }

    // 释放一个普通引用；最终删除由 socket 清理线程执行。
    void Release()
    {
        nRefCount--;
    }



    // 记录对端已知库存，防止重复 inv。
    void AddInventoryKnown(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_inventory)
            setInventoryKnown.insert(inv);
    }

    // 对端尚未知时，加入待通告队列。
    void PushInventory(const CInv& inv)
    {
        CRITICAL_BLOCK(cs_inventory)
            if (!setInventoryKnown.count(inv))
                vInventoryToSend.push_back(inv);
    }

    // 安排 getdata；同一对象每次重试至少间隔两分钟。
    void AskFor(const CInv& inv)
    {
        // We're using mapAskFor as a priority queue,
        // the key is the earliest time the request can be sent
        int64& nRequestTime = mapAlreadyAskedFor[inv];
        printf("askfor %s  %I64d\n", inv.ToString().c_str(), nRequestTime);

        // Make sure not to reuse time indexes to keep things in the same order
        int64 nNow = (GetTime() - 1) * 1000000;
        static int64 nLastTime;
        nLastTime = nNow = max(nNow, ++nLastTime);

        // Each retry is 2 minutes after the last
        nRequestTime = max(nRequestTime + 2 * 60 * 1000000, nNow);
        mapAskFor.insert(make_pair(nRequestTime, inv));
    }



    // 开始原子组包：锁定 vSend，先写 payload 长度为 0 的消息头。
    void BeginMessage(const char* pszCommand)
    {
        EnterCriticalSection(&cs_vSend);
        if (nPushPos != -1)
            AbortMessage();
        nPushPos = vSend.size();
        vSend << CMessageHeader(pszCommand, 0);
        printf("sending: %-12s ", pszCommand);
    }

    // 回滚未完成消息并释放发送锁。
    void AbortMessage()
    {
        if (nPushPos == -1)
            return;
        vSend.resize(nPushPos);
        nPushPos = -1;
        LeaveCriticalSection(&cs_vSend);
        printf("(aborted)\n");
    }

    // 回填 payload 长度，提交消息并释放发送锁。
    void EndMessage()
    {
        extern int nDropMessagesTest;
        if (nDropMessagesTest > 0 && GetRand(nDropMessagesTest) == 0)
        {
            printf("dropmessages DROPPING SEND MESSAGE\n");
            AbortMessage();
            return;
        }

        if (nPushPos == -1)
            return;

        // Patch in the size
        unsigned int nSize = vSend.size() - nPushPos - sizeof(CMessageHeader);
        memcpy((char*)&vSend[nPushPos] + offsetof(CMessageHeader, nMessageSize), &nSize, sizeof(nSize));

        printf("(%d bytes)  ", nSize);
        //for (int i = nPushPos+sizeof(CMessageHeader); i < min(vSend.size(), nPushPos+sizeof(CMessageHeader)+20U); i++)
        //    printf("%02x ", vSend[i] & 0xff);
        printf("\n");

        nPushPos = -1;
        LeaveCriticalSection(&cs_vSend);
    }

    // 仅在 payload 非空时提交，常用于批量消息。
    void EndMessageAbortIfEmpty()
    {
        if (nPushPos == -1)
            return;
        int nSize = vSend.size() - nPushPos - sizeof(CMessageHeader);
        if (nSize > 0)
            EndMessage();
        else
            AbortMessage();
    }

    // 调试辅助：返回当前正在组装的消息命令。
    const char* GetMessageCommand() const
    {
        if (nPushPos == -1)
            return "";
        return &vSend[nPushPos] + offsetof(CMessageHeader, pchCommand);
    }




    // PushMessage 各重载执行“写头—序列化参数—回填长度”；
    // 异常时统一回滚，真正的 socket 发送稍后异步进行。
    void PushMessage(const char* pszCommand)
    {
        try
        {
            BeginMessage(pszCommand);
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1>
    void PushMessage(const char* pszCommand, const T1& a1)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
    {
        try
        {
            BeginMessage(pszCommand);
            vSend << a1 << a2 << a3 << a4;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }


    // 发送带随机回复 ID 的请求并登记一次性回调。
    void PushRequest(const char* pszCommand,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply);
    }

    template<typename T1>
    void PushRequest(const char* pszCommand, const T1& a1,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1);
    }

    template<typename T1, typename T2>
    void PushRequest(const char* pszCommand, const T1& a1, const T2& a2,
                     void (*fn)(void*, CDataStream&), void* param1)
    {
        uint256 hashReply;
        RAND_bytes((unsigned char*)&hashReply, sizeof(hashReply));

        CRITICAL_BLOCK(cs_mapRequests)
            mapRequests[hashReply] = CRequestTracker(fn, param1);

        PushMessage(pszCommand, hashReply, a1, a2);
    }



    // 早期发布/订阅频道管理。
    bool IsSubscribed(unsigned int nChannel);
    void Subscribe(unsigned int nChannel, unsigned int nHops=0);
    void CancelSubscribe(unsigned int nChannel);
    void Disconnect();
};










// 向全部连接排入 inv 通告；每个 CNode 自行去重。
inline void RelayInventory(const CInv& inv)
{
    // Put on lists to offer to the other nodes
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            pnode->PushInventory(inv);
}

// 按网络格式序列化对象并交给中继缓存。
template<typename T>
void RelayMessage(const CInv& inv, const T& a)
{
    CDataStream ss(SER_NETWORK);
    ss.reserve(10000);
    ss << a;
    RelayMessage(inv, ss);
}

// 保存原始字节 15 分钟，再广播库存标识。
// 保留原始序列化可避免新版本字段被旧节点解析后丢失。
template<>
inline void RelayMessage<>(const CInv& inv, const CDataStream& ss)
{
    CRITICAL_BLOCK(cs_mapRelay)
    {
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay[inv] = ss;
        vRelayExpiration.push_back(make_pair(GetTime() + 15 * 60, inv));
    }

    RelayInventory(inv);
}








//
// Templates for the publish and subscription system.
// The object being published as T& obj needs to have:
//   a set<unsigned int> setSources member
//   specializations of AdvertInsert and AdvertErase
// Currently implemented for CTable and CProduct.
//
// 这是早期 Bitcoin 内置市场原型的传播层，与交易/区块共识无关。

// 记录来源，首次插入后按跳数或订阅关系继续转发。
template<typename T>
void AdvertStartPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Add to sources
    obj.setSources.insert(pfrom->addr.ip);

    if (!AdvertInsert(obj))
        return;

    // Relay
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("publish", nChannel, nHops, obj);
}

// 广播取消并从本地广告表删除对象。
template<typename T>
void AdvertStopPublish(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    uint256 hash = obj.GetHash();

    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode != pfrom && (nHops < PUBLISH_HOPS || pnode->IsSubscribed(nChannel)))
                pnode->PushMessage("pub-cancel", nChannel, nHops, hash);

    AdvertErase(obj);
}

// 对端断开时移除来源；已无来源则停止发布。
template<typename T>
void AdvertRemoveSource(CNode* pfrom, unsigned int nChannel, unsigned int nHops, T& obj)
{
    // Remove a source
    obj.setSources.erase(pfrom->addr.ip);

    // If no longer supported by any sources, cancel it
    if (obj.setSources.empty())
        AdvertStopPublish(pfrom, nChannel, nHops, obj);
}
