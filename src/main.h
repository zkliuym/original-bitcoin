// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// main.h — Bitcoin v0.1.3 核心数据模型与主流程接口
//=============================================================================
//
// 【本文件功能】
//   定义交易、钱包交易、区块、内存/磁盘索引和区块定位器等核心类型，并声明
//   验证、接入主链、内存池、挖矿、网络消息处理及钱包收发所需的主要入口。
//
// 【在整个系统中的作用】
//   1. 共识数据模型：CTransaction / CBlock 的序列化字段决定交易哈希、区块哈希
//      和网络/磁盘格式；CheckTransaction、CheckBlock、ConnectInputs 等参与验证。
//   2. 链状态索引：CBlockIndex 构成内存中的链树，CDiskBlockIndex 是其可持久化形态；
//      mapBlockIndex、pindexBest、nBestHeight 描述当前已知最佳链。
//   3. 钱包视图：CMerkleTx 证明交易位于某区块，CWalletTx 再附加本机收款时间、
//      支持交易、订单信息和已花费状态。
//   4. 节点主流程接口：ProcessMessage / SendMessages 连接网络层，AcceptTransaction
//      连接内存池，AcceptBlock / ConnectBlock 连接区块链数据库。
//
// 【与 main.cpp 的分工】
//   本文件以“数据结构、短小内联逻辑、跨模块函数声明”为主；main.cpp 实现需要
//   数据库、全局链状态或完整验证上下文的重型流程。阅读声明时可到 main.cpp 搜索
//   同名函数，顺着“接收消息 → 校验交易/区块 → 更新索引与钱包”的调用链理解。
//
// 【建议阅读顺序】
//   常量与全局状态 → CDiskTxPos / COutPoint → CTxIn / CTxOut → CTransaction
//   → CMerkleTx / CWalletTx → CTxIndex → CBlock → CBlockIndex / CDiskBlockIndex
//   → CBlockLocator。序列化细节可对照 serialize.h，脚本规则可对照 script.h。
//
//=============================================================================

// 前置声明：打破交易、区块、钱包、磁盘索引之间的循环依赖。
class COutPoint;
class CInPoint;
class CDiskTxPos;
class CCoinBase;
class CTxIn;
class CTxOut;
class CTransaction;
class CBlock;
class CBlockIndex;
class CWalletTx;
class CKeyItem;

// 单个网络消息/序列化对象允许的最大尺寸：0x02000000，即 32 MiB。
static const unsigned int MAX_SIZE = 0x02000000;
// 比特币最小记账单位换算：1 BTC = 100,000,000 个基础单位（后称 satoshi）。
static const int64 COIN = 100000000;
// 旧版界面与手续费计算使用的“分”：0.01 BTC = 1,000,000 个基础单位。
static const int64 CENT = 1000000;
// coinbase 输出至少等待 100 个后续区块后才允许作为可花费余额。
static const int COINBASE_MATURITY = 100;

// 工作量证明目标上限；目标越大难度越低，这是本版本允许的最低难度边界。
static const CBigNum bnProofOfWorkLimit(~uint256(0) >> 32);





// 主链状态锁：访问下列区块索引与最佳链全局状态时用于串行化。
extern CCriticalSection cs_main;
// 区块哈希 → 内存索引节点；保存已知链树（主链及分叉）的快速查找入口。
extern map<uint256, CBlockIndex*> mapBlockIndex;
// 创世区块哈希及其内存索引指针。
extern const uint256 hashGenesisBlock;
extern CBlockIndex* pindexGenesisBlock;
// 当前最佳链的高度、链尖哈希和链尖索引。
extern int nBestHeight;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
// 交易集合变化计数，供界面/钱包判断是否需要刷新。
extern unsigned int nTransactionsUpdated;
// 用户指定的数据目录；测试开关可按设定概率丢弃网络消息。
extern string strSetDataDir;
extern int nDropMessagesTest;

// Settings — 挖矿开关、最低交易费和入站监听地址。
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern CAddress addrIncoming;







// 文件/密钥/钱包/链索引的顶层服务接口；具体实现位于 main.cpp。
string GetAppDir();
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool AddKey(const CKey& key);
vector<unsigned char> GenerateNewKey();
bool AddToWallet(const CWalletTx& wtxIn);
void ReacceptWalletTransactions();
void RelayWalletTransactions();
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
// 挖矿主循环：组装候选区块并搜索满足 nBits 目标的 nonce。
bool BitcoinMiner();
// P2P 消息入口：解析收包、分派单条命令并生成待发送消息。
bool ProcessMessages(CNode* pfrom);
bool ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv);
bool SendMessages(CNode* pto);
// 钱包余额及创建、提交、发送交易的高层接口。
int64 GetBalance();
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& txNew, int64& nFeeRequiredRet);
bool CommitTransactionSpent(const CWalletTx& wtxNew);
bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew);











// CDiskTxPos：一笔交易在 blk*.dat 中的物理地址。
// nFile 选择块文件，nBlockPos 指向区块起点，nTxPos 指向交易序列化起点。
class CDiskTxPos
{
public:
    unsigned int nFile;
    unsigned int nBlockPos;
    unsigned int nTxPos;

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    // nFile=-1 作为“不存在/未花费”的哨兵值。
    void SetNull() { nFile = -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        if (IsNull())
            return strprintf("null");
        else
            return strprintf("(nFile=%d, nBlockPos=%d, nTxPos=%d)", nFile, nBlockPos, nTxPos);
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};




// CInPoint：内存中的“某笔交易的第 n 个输入”反向引用。
// 与可序列化的 COutPoint 不同，它只保存进程内指针，用于内存池冲突/花费跟踪。
class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = -1; }
    bool IsNull() const { return (ptx == NULL && n == -1); }
};




// COutPoint：唯一标识一枚可花费输出（前序交易哈希 + 输出下标）。
// 它是 UTXO 引用的基础键，也作为每个 CTxIn 的 prevout。
class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    // 以固定内存布局序列化 hash 和 n；该字节表示进入交易哈希。
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    // 全零哈希 + UINT_MAX 是 coinbase 输入使用的空前序输出标记。
    void SetNull() { hash = 0; n = -1; }
    bool IsNull() const { return (hash == 0 && n == -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0,6).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




//
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the
// output's public key.
//
// CTxIn：交易输入，声明要花费哪个旧输出，并携带解锁脚本。
// nSequence 在本版本中还参与终局性和同输入交易替换次序判断。
class CTxIn
{
public:
    COutPoint prevout;          // 被花费的旧交易输出
    CScript scriptSig;          // 满足旧输出 scriptPubKey 的签名/解锁数据
    unsigned int nSequence;     // UINT_MAX 表示该输入为最终版本

    CTxIn()
    {
        nSequence = UINT_MAX;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=UINT_MAX)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=UINT_MAX)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    // 输入序号为 UINT_MAX 时，不再受交易替换/锁定语义约束。
    bool IsFinal() const
    {
        return (nSequence == UINT_MAX);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        string str;
        str += strprintf("CTxIn(");
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig.begin(), scriptSig.end(), false).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
        if (nSequence != UINT_MAX)
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }

    // 钱包视角：该输入是否花费本机资金，以及对应借方金额。
    bool IsMine() const;
    int64 GetDebit() const;
};




//
// An output of a transaction.  It contains the public key that the next input
// must be able to sign with to claim it.
//
// CTxOut：交易输出，把金额锁定到 scriptPubKey 描述的花费条件。
// 后续输入用 COutPoint 引用它，并提供能够通过脚本验证的 scriptSig。
class CTxOut
{
public:
    int64 nValue;               // 基础单位计价的输出金额
    CScript scriptPubKey;       // 锁定脚本/收款条件

public:
    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull()
    {
        return (nValue == -1);
    }

    // 输出哈希是其完整序列化结果的双 SHA-256，主要供辅助识别/调试。
    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    // 钱包视角：脚本是否属于本机；若属于则计入贷方金额。
    bool IsMine() const
    {
        return ::IsMine(scriptPubKey);
    }

    int64 GetCredit() const
    {
        if (IsMine())
            return nValue;
        return 0;
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    string ToString() const
    {
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";
        return strprintf("CTxOut(nValue=%I64d.%08I64d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString().substr(0,24).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




//
// The basic transaction that is broadcasted on the network and contained in
// blocks.  A transaction can contain multiple inputs and outputs.
//
// CTransaction：网络广播并被区块收录的基础交易。
// txid 由版本、输入、输出和锁定时间的序列化结果计算；钱包元数据不在其中。
class CTransaction
{
public:
    int nVersion;               // 交易格式版本
    vector<CTxIn> vin;          // 消耗的旧输出集合
    vector<CTxOut> vout;        // 新创建的输出集合
    int nLockTime;              // 0 或达到指定区块高度后才最终生效


    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    )

    void SetNull()
    {
        nVersion = 1;
        vin.clear();
        vout.clear();
        nLockTime = 0;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    // 计算交易标识 txid：对交易共识字段序列化后做双 SHA-256。
    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    // 判断锁定时间和所有输入序号是否允许交易在当前最佳高度生效。
    bool IsFinal() const
    {
        if (nLockTime == 0 || nLockTime < nBestHeight)
            return true;
        foreach(const CTxIn& txin, vin)
            if (!txin.IsFinal())
                return false;
        return true;
    }

    // 比较两笔花费相同 prevout 的交易，依据最小差异 sequence 判断替换新旧。
    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = UINT_MAX;
        for (int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    // coinbase 只有一个输入，且该输入引用空 prevout；它用于创建区块奖励。
    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    // 无链上下文的基础结构检查：输入/输出非空、金额非负、coinbase 脚本长度合法。
    // 它不检查签名、旧输出是否存在或是否已花费；那些由 ConnectInputs 完成。
    bool CheckTransaction() const
    {
        // Basic checks that don't depend on any context
        if (vin.empty() || vout.empty())
            return error("CTransaction::CheckTransaction() : vin or vout empty");

        // Check for negative values
        foreach(const CTxOut& txout, vout)
            if (txout.nValue < 0)
                return error("CTransaction::CheckTransaction() : txout.nValue negative");

        if (IsCoinBase())
        {
            if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
                return error("CTransaction::CheckTransaction() : coinbase script size");
        }
        else
        {
            foreach(const CTxIn& txin, vin)
                if (txin.prevout.IsNull())
                    return error("CTransaction::CheckTransaction() : prevout is null");
        }

        return true;
    }

    // 钱包视角的归属与金额汇总：借方来自本机拥有的 prevout，贷方来自本机输出。
    bool IsMine() const
    {
        foreach(const CTxOut& txout, vout)
            if (txout.IsMine())
                return true;
        return false;
    }

    int64 GetDebit() const
    {
        int64 nDebit = 0;
        foreach(const CTxIn& txin, vin)
            nDebit += txin.GetDebit();
        return nDebit;
    }

    int64 GetCredit() const
    {
        int64 nCredit = 0;
        foreach(const CTxOut& txout, vout)
            nCredit += txout.GetCredit();
        return nCredit;
    }

    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        foreach(const CTxOut& txout, vout)
        {
            if (txout.nValue < 0)
                throw runtime_error("CTransaction::GetValueOut() : negative value");
            nValueOut += txout.nValue;
        }
        return nValueOut;
    }

    // 按序列化字节数估算最低手续费；小额/小尺寸交易可走折扣分支。
    int64 GetMinFee(bool fDiscount=false) const
    {
        unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK);
        if (fDiscount && nBytes < 10000)
            return 0;
        return (1 + (int64)nBytes / 1000) * CENT;
    }



    // 按 CDiskTxPos 从块文件直接反序列化交易；可选返回定位后的文件句柄。
    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
        CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
        if (!filein)
            return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

        // Read transaction
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return error("CTransaction::ReadFromDisk() : fseek failed");
        filein >> *this;

        // Return file pointer
        if (pfileRet)
        {
            if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
                return error("CTransaction::ReadFromDisk() : second fseek failed");
            *pfileRet = filein.release();
        }
        return true;
    }


    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    string ToString() const
    {
        string str;
        str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%d, vout.size=%d, nLockTime=%d)\n",
            GetHash().ToString().substr(0,6).c_str(),
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
        for (int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }



    // 断开/连接输入会回滚或写入 CTxIndex 的花费记录。
    bool DisconnectInputs(CTxDB& txdb);
    // 完整输入验证入口：读取旧交易、检查未花费与脚本、累计手续费并更新测试索引池。
    // fBlock/fMiner 区分接块和挖矿预检上下文，nMinFee 指定最低费用门槛。
    bool ConnectInputs(CTxDB& txdb, map<uint256, CTxIndex>& mapTestPool, CDiskTxPos posThisTx, int nHeight, int64& nFees, bool fBlock, bool fMiner, int64 nMinFee=0);
    // 轻客户端路径的输入连接检查。
    bool ClientConnectInputs();

    // 验证并接纳到内存池；pfMissingInputs 用于区分缺父交易与一般无效。
    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true, bool* pfMissingInputs=NULL);

    bool AcceptTransaction(bool fCheckInputs=true, bool* pfMissingInputs=NULL)
    {
        CTxDB txdb("r");
        return AcceptTransaction(txdb, fCheckInputs, pfMissingInputs);
    }

protected:
    // 真正写入全局内存池及 prevout 占用表的内部步骤。
    bool AddToMemoryPool();
public:
    bool RemoveFromMemoryPool();
};





//
// A transaction with a merkle branch linking it to the block chain
//
// CMerkleTx：在基础交易上附加所在区块和 Merkle 证明。
// 它让钱包无需保存完整区块，也能验证 txid 是否属于 hashBlock 的 Merkle 根。
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;                  // 收录该交易的区块哈希
    vector<uint256> vMerkleBranch;      // 从交易叶子到 Merkle 根的兄弟哈希路径
    int nIndex;                         // 交易在区块 vtx 中的位置，-1 表示未知

    // memory only — Merkle 路径校验缓存，不写入网络/磁盘。
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }

    // coinbase 未成熟时不计入可用贷方，普通交易沿用基础类金额计算。
    int64 GetCredit() const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;
        return CTransaction::GetCredit();
    }

    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    // 从区块建立证明并返回主链深度；深度也决定 coinbase 尚需等待的区块数。
    int SetMerkleBranch(const CBlock* pblock=NULL);
    int GetDepthInMainChain() const;
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptTransaction() { CTxDB txdb("r"); return AcceptTransaction(txdb); }
};




//
// A transaction with a bunch of additional info that only the owner cares
// about.  It includes any unrecorded transactions needed to link it back
// to the block chain.
//
// CWalletTx：钱包持久化的一笔交易 = CMerkleTx + 仅本机关心的元数据。
// 这些附加字段不影响 txid；用于余额展示、重播未确认交易和记录付款表单信息。
class CWalletTx : public CMerkleTx
{
public:
    vector<CMerkleTx> vtxPrev;                  // 支撑本交易输入的祖先交易
    map<string, string> mapValue;               // 可扩展钱包键值元数据
    vector<pair<string, string> > vOrderForm;   // 付款/订单表单字段
    unsigned int fTimeReceivedIsTxTime;         // 接收时间是否可视为交易时间
    unsigned int nTimeReceived;                 // 本节点首次收到的时间
    char fFromMe;                               // 是否由本钱包创建
    char fSpent;                                // 钱包输出是否已被花费
    //// probably need to sign the order info so know it came from payer

    // memory only
    mutable unsigned int nTimeDisplayed;


    CWalletTx()
    {
        Init();
    }

    CWalletTx(const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    CWalletTx(const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init();
    }

    void Init()
    {
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        fFromMe = false;
        fSpent = false;
        nTimeDisplayed = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CMerkleTx*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(vtxPrev);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);
    )

    // 按 txid 写入 wallet.dat。
    bool WriteToDisk()
    {
        return CWalletDB().WriteTx(GetHash(), *this);
    }


    int64 GetTxTime() const;

    // 补齐祖先交易、验证接纳并向对等节点转发钱包交易。
    void AddSupportingTransactions(CTxDB& txdb);

    bool AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs=true);
    bool AcceptWalletTransaction() { CTxDB txdb("r"); return AcceptWalletTransaction(txdb); }

    void RelayWalletTransaction(CTxDB& txdb);
    void RelayWalletTransaction() { CTxDB txdb("r"); RelayWalletTransaction(txdb); }
};




//
// A txdb record that contains the disk location of a transaction and the
// locations of transactions that spend its outputs.  vSpent is really only
// used as a flag, but having the location is very helpful for debugging.
//
// CTxIndex：txdb 中的交易索引记录。
// pos 指向交易本体，vSpent 与每个 vout 一一对应；空位置表示未花费，非空位置
// 指向花费该输出的后续交易，既支持双花检查，也方便调试追踪。
class CTxIndex
{
public:
    CDiskTxPos pos;                 // 当前交易在块文件中的位置
    vector<CDiskTxPos> vSpent;      // 每个输出的花费交易位置

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        if (a.pos != b.pos || a.vSpent.size() != b.vSpent.size())
            return false;
        for (int i = 0; i < a.vSpent.size(); i++)
            if (a.vSpent[i] != b.vSpent[i])
                return false;
        return true;
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
};





//
// Nodes collect new transactions into a block, hash them into a hash tree,
// and scan through nonce values to make the block's hash satisfy proof-of-work
// requirements.  When they solve the proof-of-work, they broadcast the block
// to everyone and the block is added to the block chain.  The first transaction
// in the block is a special one that creates a new coin owned by the creator
// of the block.
//
// Blocks are appended to blk0001.dat files on disk.  Their location on disk
// is indexed by CBlockIndex objects in memory.
//
// CBlock：区块头 + 交易列表。
// 区块头参与 PoW 哈希；vtx 通过 Merkle 树承诺到 hashMerkleRoot；vMerkleTree
// 只是按需构建的内存缓存，不进入序列化。
class CBlock
{
public:
    // header — 这六个字段连续构成区块头，也是 GetHash 的输入。
    int nVersion;                   // 区块格式版本
    uint256 hashPrevBlock;          // 前一区块哈希，形成链
    uint256 hashMerkleRoot;         // 本区块所有交易的 Merkle 根
    unsigned int nTime;             // 矿工声明的区块时间
    unsigned int nBits;             // 压缩编码的 PoW 目标
    unsigned int nNonce;            // 挖矿搜索变量

    // network and disk — 完整区块网络传播及落盘时包含的交易。
    vector<CTransaction> vtx;

    // memory only — 展平的 Merkle 树缓存。
    mutable vector<uint256> vMerkleTree;


    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        // ConnectBlock depends on vtx being last so it can calculate offset
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
            READWRITE(vtx);
        else if (fRead)
            const_cast<CBlock*>(this)->vtx.clear();
    )

    void SetNull()
    {
        nVersion = 1;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vMerkleTree.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // 仅哈希区块头从 nVersion 到 nNonce 的连续字节，不包含 vtx。
    uint256 GetHash() const
    {
        return Hash(BEGIN(nVersion), END(nNonce));
    }


    // 自底向上构建 Merkle 树；奇数层复制最后一个节点，并返回根哈希。
    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        foreach(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    // 生成第 nIndex 笔交易的兄弟哈希路径。
    vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    // 用叶子哈希、分支和左右位置重算 Merkle 根，供 CMerkleTx 验证包含关系。
    static uint256 CheckMerkleBranch(uint256 hash, const vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        foreach(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }


    // 以“网络魔数 + 长度 + 区块”格式追加到 blk*.dat，并返回文件及偏移。
    bool WriteToDisk(bool fWriteTransactions, unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = AppendBlockFile(nFileRet);
        if (!fileout)
            return error("CBlock::WriteToDisk() : AppendBlockFile failed");
        if (!fWriteTransactions)
            fileout.nType |= SER_BLOCKHEADERONLY;

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        nBlockPosRet = ftell(fileout);
        if (nBlockPosRet == -1)
            return error("CBlock::WriteToDisk() : ftell failed");
        fileout << *this;

        return true;
    }

    // 从块文件读取完整区块或仅区块头，并立即检查目标范围及 PoW 哈希。
    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions)
    {
        SetNull();

        // Open history file to read
        CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
        if (!filein)
            return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
        if (!fReadTransactions)
            filein.nType |= SER_BLOCKHEADERONLY;

        // Read block
        filein >> *this;

        // Check the header
        if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
            return error("CBlock::ReadFromDisk() : nBits errors in block header");
        if (GetHash() > CBigNum().SetCompact(nBits).getuint256())
            return error("CBlock::ReadFromDisk() : GetHash() errors in block header");

        return true;
    }



    void print() const
    {
        printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%d)\n",
            GetHash().ToString().substr(0,14).c_str(),
            nVersion,
            hashPrevBlock.ToString().substr(0,14).c_str(),
            hashMerkleRoot.ToString().substr(0,6).c_str(),
            nTime, nBits, nNonce,
            vtx.size());
        for (int i = 0; i < vtx.size(); i++)
        {
            printf("  ");
            vtx[i].print();
        }
        printf("  vMerkleTree: ");
        for (int i = 0; i < vMerkleTree.size(); i++)
            printf("%s ", vMerkleTree[i].ToString().substr(0,6).c_str());
        printf("\n");
    }


    // 区块奖励、链状态连接/断开、结构校验和接纳主流程的重型实现位于 main.cpp。
    int64 GetBlockValue(int64 nFees) const;
    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool ReadFromDisk(const CBlockIndex* blockindex, bool fReadTransactions);
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
    bool CheckBlock() const;
    bool AcceptBlock();
};






//
// The block chain is a tree shaped structure starting with the
// genesis block at the root, with each block potentially having multiple
// candidates to be the next block.  pprev and pnext link a path through the
// main/longest chain.  A blockindex may have multiple pprev pointing back
// to it, but pnext will only point forward to the longest branch, or will
// be null if the block is not part of the longest chain.
//
// CBlockIndex：一个已知区块在内存中的索引节点。
// pprev 连接父区块，主链节点的 pnext 指向下一块；分叉通常只有 pprev。
// 它缓存块文件位置和区块头字段，避免为链遍历反复读取完整区块。
class CBlockIndex
{
public:
    const uint256* phashBlock;       // 指向 mapBlockIndex 键中的稳定哈希
    CBlockIndex* pprev;              // 父区块索引
    CBlockIndex* pnext;              // 主链上的后继，分叉末端为空
    unsigned int nFile;              // 所在 blk*.dat 编号
    unsigned int nBlockPos;          // 区块在文件中的偏移
    int nHeight;                     // 从创世块起的链高度

    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;


    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
    }

    // 返回此索引代表的区块哈希；phashBlock 必须已由索引装载流程设置。
    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    // 有主链后继，或自身就是当前链尖时，视为位于主链。
    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
    }

    // 用空区块覆盖磁盘位置；这是早期实现的物理删除辅助操作。
    bool EraseBlockFromDisk()
    {
        // Open history file
        CAutoFile fileout = OpenBlockFile(nFile, nBlockPos, "rb+");
        if (!fileout)
            return false;

        // Overwrite with empty null block
        CBlock block;
        block.SetNull();
        fileout << block;

        return true;
    }

    // 使用最近 11 个祖先区块时间的中位数，降低单个异常时间戳的影响。
    enum { nMedianTimeSpan=11 };

    int64 GetMedianTimePast() const
    {
        unsigned int pmedian[nMedianTimeSpan];
        unsigned int* pbegin = &pmedian[nMedianTimeSpan];
        unsigned int* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->nTime;

        sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    int64 GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan/2; i++)
        {
            if (!pindex->pnext)
                return nTime;
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }



    string ToString() const
    {
        return strprintf("CBlockIndex(nprev=%08x, pnext=%08x, nFile=%d, nBlockPos=%-6d nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, pnext, nFile, nBlockPos, nHeight,
            hashMerkleRoot.ToString().substr(0,6).c_str(),
            GetBlockHash().ToString().substr(0,14).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};



//
// Used to marshal pointers into hashes for db storage.
//
// CDiskBlockIndex：CBlockIndex 的数据库可序列化版本。
// 内存指针 pprev/pnext 不能跨进程保存，因此改存 hashPrev/hashNext；加载时再由
// mapBlockIndex 解析为指针。其 GetBlockHash 会从保存的区块头字段重建哈希。
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;             // 父索引指针的持久化替代
    uint256 hashNext;             // 主链后继指针的持久化替代

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    // 重建完整区块头并计算哈希，不依赖基类的 phashBlock 指针。
    uint256 GetBlockHash() const
    {
        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        return block.GetHash();
    }


    string ToString() const
    {
        string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().substr(0,14).c_str(),
            hashNext.ToString().substr(0,14).c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};








//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
// CBlockLocator：节点间寻找共同祖先的稀疏区块哈希列表。
// 前 10 项逐块回溯，之后步长指数增长，既覆盖近期分叉又控制消息大小；
// getblocks/getheaders 类同步流程可据此快速定位双方共同主链起点。
class CBlockLocator
{
protected:
    vector<uint256> vHave;       // 从新到旧排列的已知区块哈希采样
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    // 从给定链节点构造指数退避采样，并确保最后包含创世区块。
    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            vHave.push_back(pindex->GetBlockHash());

            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev;
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back(hashGenesisBlock);
    }

    // 返回定位器中第一个位于本机主链的索引，即双方最近共同祖先。
    CBlockIndex* GetBlockIndex()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return pindex;
            }
        }
        return pindexGenesisBlock;
    }

    // 与 GetBlockIndex 对应，但只返回共同祖先哈希。
    uint256 GetBlockHash()
    {
        // Find the first block the caller has in the main chain
        foreach(const uint256& hash, vHave)
        {
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return hash;
            }
        }
        return hashGenesisBlock;
    }

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};












// 内存池：尚未进入区块的交易；钱包表：txid → 本机钱包交易。
extern map<uint256, CTransaction> mapTransactions;
extern map<uint256, CWalletTx> mapWallet;
// 钱包变更通知队列及其锁。
extern vector<pair<uint256, bool> > vWalletUpdated;
extern CCriticalSection cs_mapWallet;
// 本机密钥表：公钥字节 → 私钥，以及公钥哈希 → 完整公钥；由 cs_mapKeys 保护。
extern map<vector<unsigned char>, CPrivKey> mapKeys;
extern map<uint160, vector<unsigned char> > mapPubKeys;
extern CCriticalSection cs_mapKeys;
// 节点默认用户密钥。
extern CKey keyUser;
