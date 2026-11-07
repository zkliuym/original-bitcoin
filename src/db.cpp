// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// db.cpp — Bitcoin v0.1.3 数据库环境、索引与钱包加载实现
//=============================================================================
//
// 【本文件功能】
//   初始化/关闭 Berkeley DB 环境，实现 CDB 文件生命周期与刷盘，并实现
//   blkindex.dat、addr.dat、reviews.dat、wallet.dat 的具体键值读写和启动恢复。
//
// 【在整个系统中的作用】
//   程序启动时，本文件把磁盘记录恢复成 mapBlockIndex、mapWallet、mapKeys、
//   mapAddresses 等核心内存状态；运行时又把链状态、钱包变化和节点地址持久化。
//   它是 serialize.h 的对象编码与 main/wallet/net 内存模型之间的落盘桥梁。
//
// 【阅读主线】
//   CDB 构造/DBFlush（环境）→ CTxDB::LoadBlockIndex（链索引）
//   → CAddrDB::LoadAddresses（节点池）→ CWalletDB::LoadWallet（钱包状态）。
//
//=============================================================================

#include "headers.h"






//
// CDB — 共享 Berkeley DB 环境
//

static CCriticalSection cs_db;             // 保护环境初始化和文件引用计数
static bool fDbEnvInit = false;            // dbenv 是否已成功打开
DbEnv dbenv(0);                            // 所有 *.dat 数据库共享的环境
static map<string, int> mapFileUseCount;   // 文件名 -> 当前 CDB 句柄数

// 静态析构守卫：进程正常退出时兜底关闭共享环境。
class CDBInit
{
public:
    CDBInit()
    {
    }
    ~CDBInit()
    {
        if (fDbEnvInit)
        {
            dbenv.close(0);
            fDbEnvInit = false;
        }
    }
}
instance_of_cdbinit;


CDB::CDB(const char* pszFile, const char* pszMode, bool fTxn) : pdb(NULL)
{
    int ret;
    if (pszFile == NULL)
        return;

    // 模式字符沿用旧式约定：c=可创建，+ 或 w=可写，其余为只读。
    bool fCreate = strchr(pszMode, 'c');
    bool fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;
    else if (fReadOnly)
        nFlags |= DB_RDONLY;
    if (!fReadOnly || fTxn)
        nFlags |= DB_AUTO_COMMIT;

    CRITICAL_BLOCK(cs_db)
    {
        if (!fDbEnvInit)
        {
            // 首个数据库句柄负责一次性建立环境。事务日志放在 database\，
            // 数据文件本身放在应用目录；DB_RECOVER 会在异常退出后回放日志。
            string strAppDir = GetAppDir();
            string strLogDir = strAppDir + "\\database";
            _mkdir(strLogDir.c_str());
            printf("dbenv.open strAppDir=%s\n", strAppDir.c_str());

            dbenv.set_lg_dir(strLogDir.c_str());
            dbenv.set_lg_max(10000000);       // 单个日志文件约 10 MB
            dbenv.set_lk_max_locks(10000);
            dbenv.set_lk_max_objects(10000);
            dbenv.set_errfile(fopen("db.log", "a")); /// debug
            ///dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1); /// 早期版本曾导致损坏，故禁用
            ret = dbenv.open(strAppDir.c_str(),
                             DB_CREATE     |
                             DB_INIT_LOCK  |
                             DB_INIT_LOG   |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN   |
                             DB_THREAD     |
                             DB_PRIVATE    |
                             DB_RECOVER,
                             0);
            if (ret > 0)
                throw runtime_error(strprintf("CDB() : error %d opening database environment\n", ret));
            fDbEnvInit = true;
        }

        strFile = pszFile;
        ++mapFileUseCount[strFile];
    }

    // 每个文件内部使用名为 "main" 的 B-tree 子数据库。
    pdb = new Db(&dbenv, 0);

    ret = pdb->open(NULL,      // Txn pointer
                    pszFile,   // Filename
                    "main",    // Logical db name
                    DB_BTREE,  // Database type
                    nFlags,    // Flags
                    0);

    if (ret > 0)
    {
        delete pdb;
        pdb = NULL;
        CRITICAL_BLOCK(cs_db)
            --mapFileUseCount[strFile];
        strFile = "";
        throw runtime_error(strprintf("CDB() : can't open database file %s, error %d\n", pszFile, ret));
    }

    // 新库写入客户端格式版本，供未来迁移/兼容判断。
    if (fCreate && !Exists(string("version")))
        WriteVersion(VERSION);

    RandAddSeed();
}

void CDB::Close()
{
    if (!pdb)
        return;
    // 关闭时若仍有嵌套事务，从最外层 abort 会连带撤销其子事务。
    if (!vTxn.empty())
        vTxn.front()->abort();
    vTxn.clear();
    pdb->close(0);
    delete pdb;
    pdb = NULL;
    dbenv.txn_checkpoint(0, 0, 0);

    CRITICAL_BLOCK(cs_db)
        --mapFileUseCount[strFile];

    RandAddSeed();
}

void DBFlush(bool fShutdown)
{
    // 将事务日志 checkpoint 到数据文件；对引用数为 0 的文件重置 LSN。
    // fShutdown=true 时还清理归档日志并关闭整个共享环境。
    printf("DBFlush(%s)\n", fShutdown ? "true" : "false");
    CRITICAL_BLOCK(cs_db)
    {
        dbenv.txn_checkpoint(0, 0, 0);
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            if (nRefCount == 0)
            {
                dbenv.lsn_reset(strFile.c_str(), 0);
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
        if (fShutdown)
        {
            char** listp;
            if (mapFileUseCount.empty())
                dbenv.log_archive(&listp, DB_ARCH_REMOVE);
            dbenv.close(0);
            fDbEnvInit = false;
        }
    }
}






//
// CTxDB — blkindex.dat 的交易/区块索引
//

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
    assert(!fClient);
    txindex.SetNull();
    // 键：("tx", txid)；值：CTxIndex
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    assert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    assert(!fClient);

    // 只建立位置/输出状态索引，交易正文仍从 blkNNNN.dat 按 pos 读取。
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    assert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    assert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadOwnerTxes(uint160 hash160, int nMinHeight, vector<CTransaction>& vtx)
{
    assert(!fClient);
    vtx.clear();

    // Get cursor
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    // 复合键布局为 "owner" + hash160 + CDiskTxPos。先按前缀定位，
    // 再顺序扫描，遇到类型或 owner 改变时即离开该连续键区间。
    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << string("owner") << hash160 << CDiskTxPos(0, 0, 0);
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
            return false;

        // Unserialize
        string strType;
        uint160 hashItem;
        CDiskTxPos pos;
        ssKey >> strType >> hashItem >> pos;
        int nItemHeight;
        ssValue >> nItemHeight;

        // Read transaction
        if (strType != "owner" || hashItem != hash160)
            break;
        if (nItemHeight >= nMinHeight)
        {
            vtx.resize(vtx.size()+1);
            if (!vtx.back().ReadFromDisk(pos))
                return false;
        }
    }
    return true;
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
    assert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    // 键：("blockindex", block hash)；值含前后块哈希、文件位置和块头字段。
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::EraseBlockIndex(uint256 hash)
{
    return Erase(make_pair(string("blockindex"), hash));
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

CBlockIndex* InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // 同一哈希只创建一个 CBlockIndex，保证所有 pprev/pnext 指针共享节点。
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // 先插入 map，再让 phashBlock 指向 map 内稳定保存的 key。
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    // 第一阶段：按 ("blockindex", 0) 定位并扫描同前缀的全部磁盘索引。
    // Get cursor
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey;
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("blockindex"), uint256(0));
        CDataStream ssValue;
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
            return false;

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType == "blockindex")
        {
            CDiskBlockIndex diskindex;
            ssValue >> diskindex;

            // 将磁盘结构转成内存节点；InsertBlockIndex 会为尚未扫描到的
            // 前驱/后继先创建占位节点，之后读到相应记录时再补齐字段。
            CBlockIndex* pindexNew = InsertBlockIndex(diskindex.GetBlockHash());
            pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
            pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);
            pindexNew->nFile          = diskindex.nFile;
            pindexNew->nBlockPos      = diskindex.nBlockPos;
            pindexNew->nHeight        = diskindex.nHeight;
            pindexNew->nVersion       = diskindex.nVersion;
            pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
            pindexNew->nTime          = diskindex.nTime;
            pindexNew->nBits          = diskindex.nBits;
            pindexNew->nNonce         = diskindex.nNonce;

            // 扫描过程中识别创世块；最佳链 tip 在扫描完成后单独读取。
            if (pindexGenesisBlock == NULL && diskindex.GetBlockHash() == hashGenesisBlock)
                pindexGenesisBlock = pindexNew;
        }
        else
        {
            break;
        }
    }

    // 第二阶段："hashBestChain" 指出上次持久化的主链 tip。
    // 空库允许没有该键；已有创世块却缺失则视为数据库不一致。
    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL)
            return true;
        return error("CTxDB::LoadBlockIndex() : hashBestChain not found\n");
    }

    if (!mapBlockIndex.count(hashBestChain))
        return error("CTxDB::LoadBlockIndex() : blockindex for hashBestChain not found\n");
    // 第三阶段：把全局最佳块指针和高度接回刚重建的索引图。
    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->nHeight;
    printf("LoadBlockIndex(): hashBestChain=%s  height=%d\n", hashBestChain.ToString().substr(0,14).c_str(), nBestHeight);

    return true;
}





//
// CAddrDB — addr.dat 与 addr.txt 节点地址恢复
//

bool CAddrDB::WriteAddress(const CAddress& addr)
{
    // 键：("addr", addr.GetKey())；GetKey 通常编码服务端点。
    return Write(make_pair(string("addr"), addr.GetKey()), addr);
}

bool CAddrDB::LoadAddresses()
{
    CRITICAL_BLOCK(cs_mapAddresses)
    {
        // 先读取用户手工提供的 addr.txt，并通过 AddAddress 合并/持久化。
        CAutoFile filein = fopen("addr.txt", "rt");
        if (filein)
        {
            try
            {
                char psz[1000];
                while (fgets(psz, sizeof(psz), filein))
                {
                    CAddress addr(psz, NODE_NETWORK);
                    if (addr.ip != 0)
                        AddAddress(*this, addr);
                }
            }
            catch (...) { }
        }

        // 再扫描 addr.dat，把所有 "addr" 记录恢复到 mapAddresses。
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        loop
        {
            // Read next record
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // Unserialize
            string strType;
            ssKey >> strType;
            if (strType == "addr")
            {
                CAddress addr;
                ssValue >> addr;
                mapAddresses.insert(make_pair(addr.GetKey(), addr));
            }
        }

        //// debug print
        printf("mapAddresses:\n");
        foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            item.second.print();
        printf("-----\n");

        // Fix for possible GCC bug that manifests in mapAddresses.count in irc.cpp,
        // just need to call count here and it doesn't happen there, do not delete this!
        mapAddresses.count(vector<unsigned char>(18));
    }

    return true;
}

bool LoadAddresses()
{
    return CAddrDB("cr+").LoadAddresses();
}




//
// CReviewDB — 实验性评价/信誉记录
//

bool CReviewDB::ReadReviews(uint256 hash, vector<CReview>& vReviews)
{
    vReviews.size(); // msvc workaround, just need to do anything with vReviews
    // 键：("reviews", 被评价用户哈希)；值：该用户收到的评价列表。
    return Read(make_pair(string("reviews"), hash), vReviews);
}

bool CReviewDB::WriteReviews(uint256 hash, const vector<CReview>& vReviews)
{
    return Write(make_pair(string("reviews"), hash), vReviews);
}







//
// CWalletDB — wallet.dat 启动恢复
//

bool CWalletDB::LoadWallet(vector<unsigned char>& vchDefaultKeyRet)
{
    vchDefaultKeyRet.clear();

    //// todo: shouldn't we catch exceptions and try to recover and continue?
    // 加载期间同时锁定密钥表和钱包交易表，避免其他线程看到半恢复状态。
    CRITICAL_BLOCK(cs_mapKeys)
    CRITICAL_BLOCK(cs_mapWallet)
    {
        // Get cursor
        Dbc* pcursor = GetCursor();
        if (!pcursor)
            return false;

        loop
        {
            // Read next record
            CDataStream ssKey;
            CDataStream ssValue;
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
                return false;

            // pair 键按 first、second 连续序列化，因此先读 strType 即可分派，
            // 再从同一 ssKey 继续读该类型的标识字段。
            string strType;
            ssKey >> strType;
            if (strType == "name")
            {
                // ("name", address) -> label：恢复地址簿。
                string strAddress;
                ssKey >> strAddress;
                ssValue >> mapAddressBook[strAddress];
            }
            else if (strType == "tx")
            {
                // ("tx", txid) -> CWalletTx：恢复钱包相关交易及本地元数据。
                uint256 hash;
                ssKey >> hash;
                CWalletTx& wtx = mapWallet[hash];
                ssValue >> wtx;

                if (wtx.GetHash() != hash)
                    printf("Error in wallet.dat, hash mismatch\n");

                //// debug print
                //printf("LoadWallet  %s\n", wtx.GetHash().ToString().c_str());
                //printf(" %12I64d  %s  %s  %s\n",
                //    wtx.vout[0].nValue,
                //    DateTimeStr(wtx.nTime).c_str(),
                //    wtx.hashBlock.ToString().substr(0,14).c_str(),
                //    wtx.mapValue["message"].c_str());
            }
            else if (strType == "key")
            {
                // ("key", pubkey) -> private key：同时建立 hash160 -> pubkey 快查表。
                vector<unsigned char> vchPubKey;
                ssKey >> vchPubKey;
                CPrivKey vchPrivKey;
                ssValue >> vchPrivKey;

                mapKeys[vchPubKey] = vchPrivKey;
                mapPubKeys[Hash160(vchPubKey)] = vchPubKey;
            }
            else if (strType == "defaultkey")
            {
                // 单字符串键；返回给外层 LoadWallet 选定 keyUser。
                ssValue >> vchDefaultKeyRet;
            }
            else if (strType == "setting")  /// or settings or option or options or config?
            {
                // 只恢复本版本认识的设置；未知设置自然跳过，便于向前兼容。
                string strKey;
                ssKey >> strKey;
                if (strKey == "fGenerateBitcoins")  ssValue >> fGenerateBitcoins;
                if (strKey == "nTransactionFee")    ssValue >> nTransactionFee;
                if (strKey == "addrIncoming")       ssValue >> addrIncoming;
            }
        }
    }

    printf("fGenerateBitcoins = %d\n", fGenerateBitcoins);
    printf("nTransactionFee = %I64d\n", nTransactionFee);
    printf("addrIncoming = %s\n", addrIncoming.ToString().c_str());

    return true;
}

bool LoadWallet()
{
    // 用 "cr" 打开：不存在则创建，已有则只读加载。
    vector<unsigned char> vchDefaultKey;
    if (!CWalletDB("cr").LoadWallet(vchDefaultKey))
        return false;

    if (mapKeys.count(vchDefaultKey))
    {
        // 默认公钥能在已加载私钥表中找到：恢复用户身份密钥。
        keyUser.SetPubKey(vchDefaultKey);
        keyUser.SetPrivKey(mapKeys[vchDefaultKey]);
    }
    else
    {
        // 首次运行或默认键损坏：生成新身份密钥，并写入私钥、地址簿和默认键。
        keyUser.MakeNewKey();
        if (!AddKey(keyUser))
            return false;
        if (!SetAddressBookName(PubKeyToAddress(keyUser.GetPubKey()), "Your Address"))
            return false;
        CWalletDB().WriteDefaultKey(keyUser.GetPubKey());
    }

    return true;
}
