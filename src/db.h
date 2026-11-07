// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// db.h — Bitcoin v0.1.3 Berkeley DB 持久化接口
//=============================================================================
//
// 【本文件功能】
//   定义 Berkeley DB 的通用封装 CDB，以及区块/交易索引、钱包、节点地址、
//   评价与市场数据的专用数据库类。键和值均通过 serialize.h 的 SER_DISK
//   规则编码，因此 C++ 对象可以直接作为 B-tree 的复合键和值。
//
// 【在整个系统中的作用】
//   - blkindex.dat：保存交易位置、区块索引和最佳链哈希，供启动时重建内存链索引。
//   - wallet.dat：保存私钥、钱包交易、地址簿、默认密钥和少量运行设置。
//   - addr.dat：保存已知 P2P 节点，重启后恢复地址池。
//   - reviews.dat / market.dat：支撑早期实验性的评价信誉与市场功能。
//   - CDB 统一管理数据库环境、游标、事务及敏感序列化缓冲区的清理。
//
// 【键格式速览】
//   普通字符串键："version"、"hashBestChain"、"defaultkey"。
//   复合键通常是 pair(类型标签, 标识)，序列化后类型标签排在最前：
//   ("tx", txid)、("blockindex", blockhash)、("name", address)、
//   ("key", pubkey)、("setting", name)、("addr", endpoint key)、
//   ("user", user hash)、("reviews", recipient hash)。
//
//=============================================================================

#include <db_cxx.h>
class CTransaction;
class CTxIndex;
class CDiskBlockIndex;
class CDiskTxPos;
class COutPoint;
class CUser;
class CReview;
class CAddress;
class CWalletTx;

extern map<string, string> mapAddressBook;
extern bool fClient;


extern DbEnv dbenv;
extern void DBFlush(bool fShutdown);


// CDB：所有专用数据库的底层 RAII 包装。
// 一个对象对应环境中的一个 Berkeley DB 文件；模板方法负责把任意键/值
// 序列化为字节。vTxn 形成事务栈，最内层事务由 GetTxn() 交给读写操作。
class CDB
{
protected:
    Db* pdb;                  // 当前打开的 Berkeley DB 句柄
    string strFile;           // 文件名，也用于全局引用计数
    vector<DbTxn*> vTxn;      // 活动事务栈；末项是当前事务

    explicit CDB(const char* pszFile, const char* pszMode="r+", bool fTxn=false);
    ~CDB() { Close(); }
public:
    void Close();
private:
    CDB(const CDB&);
    void operator=(const CDB&);

protected:
    // 将 key 按 SER_DISK 编码，读取 malloc 分配的值缓冲，再反序列化为 value。
    // 结束前主动清零 key/value 字节，避免私钥等敏感内容残留。
    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        if (!pdb)
            return false;

        // Key：数据库真正看到的是序列化后的二进制键
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Read：DB_DBT_MALLOC 要求调用方在使用后 free
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pdb->get(GetTxn(), &datKey, &datValue, 0);
        memset(datKey.get_data(), 0, datKey.get_size());
        if (datValue.get_data() == NULL)
            return false;

        // Unserialize value：用同一套 SER_DISK 规则还原对象
        CDataStream ssValue((char*)datValue.get_data(), (char*)datValue.get_data() + datValue.get_size(), SER_DISK);
        ssValue >> value;

        // Clear and free memory：钱包记录可能含私钥
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datValue.get_data());
        return (ret == 0);
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite=true)
    {
        if (!pdb)
            return false;

        // Key：复合 pair 会按 first、second 顺序连续编码
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Value：对象的 IMPLEMENT_SERIALIZE 决定磁盘布局
        CDataStream ssValue(SER_DISK);
        ssValue.reserve(10000);
        ssValue << value;
        Dbt datValue(&ssValue[0], ssValue.size());

        // Write：fOverwrite=false 用于保护已存在的私钥记录
        int ret = pdb->put(GetTxn(), &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        // Clear memory in case it was a private key
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Erase
        int ret = pdb->del(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
    bool Exists(const K& key)
    {
        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Exists
        int ret = pdb->exists(GetTxn(), &datKey, 0);

        // Clear memory
        memset(datKey.get_data(), 0, datKey.get_size());
        return (ret == 0);
    }

    Dbc* GetCursor()
    {
        if (!pdb)
            return NULL;
        Dbc* pcursor = NULL;
        int ret = pdb->cursor(NULL, &pcursor, 0);
        if (ret != 0)
            return NULL;
        return pcursor;
    }

    // 游标读取一条记录。DB_SET_RANGE 可从指定前缀定位，DB_NEXT 顺序扫描；
    // 返回的键和值被复制进 CDataStream，供调用者按字段逐段解析。
    int ReadAtCursor(Dbc* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags=DB_NEXT)
    {
        // Read at cursor
        Dbt datKey;
        if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datKey.set_data(&ssKey[0]);
            datKey.set_size(ssKey.size());
        }
        Dbt datValue;
        if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datValue.set_data(&ssValue[0]);
            datValue.set_size(ssValue.size());
        }
        datKey.set_flags(DB_DBT_MALLOC);
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        if (ret != 0)
            return ret;
        else if (datKey.get_data() == NULL || datValue.get_data() == NULL)
            return 99999;

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char*)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());

        // Clear and free memory
        memset(datKey.get_data(), 0, datKey.get_size());
        memset(datValue.get_data(), 0, datValue.get_size());
        free(datKey.get_data());
        free(datValue.get_data());
        return 0;
    }

    DbTxn* GetTxn()
    {
        if (!vTxn.empty())
            return vTxn.back();
        else
            return NULL;
    }

public:
    // Berkeley DB 事务支持嵌套：新事务以当前事务为父事务。
    bool TxnBegin()
    {
        if (!pdb)
            return false;
        DbTxn* ptxn = NULL;
        int ret = dbenv.txn_begin(GetTxn(), &ptxn, 0);
        if (!ptxn || ret != 0)
            return false;
        vTxn.push_back(ptxn);
        return true;
    }

    bool TxnCommit()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->commit(0);
        vTxn.pop_back();
        return (ret == 0);
    }

    bool TxnAbort()
    {
        if (!pdb)
            return false;
        if (vTxn.empty())
            return false;
        int ret = vTxn.back()->abort();
        vTxn.pop_back();
        return (ret == 0);
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(string("version"), nVersion);
    }
};








// CTxDB（blkindex.dat）：完整节点的交易与区块元数据索引。
// 实际区块/交易正文仍在 blkNNNN.dat；本库主要保存“哈希 -> 磁盘位置/状态”。
class CTxDB : public CDB
{
public:
    CTxDB(const char* pszMode="r+", bool fTxn=false) : CDB(!fClient ? "blkindex.dat" : NULL, pszMode, fTxn) { }
private:
    CTxDB(const CTxDB&);
    void operator=(const CTxDB&);
public:
    // ("tx", txid) -> CTxIndex（磁盘位置及各输出已花费位置）
    bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);
    // 扫描 ("owner", hash160, disk position) 前缀索引，取指定高度后的相关交易。
    bool ReadOwnerTxes(uint160 hash160, int nHeight, vector<CTransaction>& vtx);
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    // ("blockindex", blockhash) -> CDiskBlockIndex
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool EraseBlockIndex(uint256 hash);
    // "hashBestChain" -> 当前主链 tip 哈希
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    // 启动恢复入口：扫描全部区块索引记录并重建 mapBlockIndex 指针图。
    bool LoadBlockIndex();
};





// CReviewDB（reviews.dat）：实验性信誉系统的持久化层。
// ("user", 用户公钥哈希) 保存传播状态；("reviews", 收件人哈希) 保存评价列表。
class CReviewDB : public CDB
{
public:
    CReviewDB(const char* pszMode="r+", bool fTxn=false) : CDB("reviews.dat", pszMode, fTxn) { }
private:
    CReviewDB(const CReviewDB&);
    void operator=(const CReviewDB&);
public:
    bool ReadUser(uint256 hash, CUser& user)
    {
        return Read(make_pair(string("user"), hash), user);
    }

    bool WriteUser(uint256 hash, const CUser& user)
    {
        return Write(make_pair(string("user"), hash), user);
    }

    bool ReadReviews(uint256 hash, vector<CReview>& vReviews);
    bool WriteReviews(uint256 hash, const vector<CReview>& vReviews);
};





// CMarketDB（market.dat）：为早期实验性市场预留的数据库。
// 此版本尚未定义专用读写接口，只有通用 CDB 能力。
class CMarketDB : public CDB
{
public:
    CMarketDB(const char* pszMode="r+", bool fTxn=false) : CDB("market.dat", pszMode, fTxn) { }
private:
    CMarketDB(const CMarketDB&);
    void operator=(const CMarketDB&);
};





// CAddrDB（addr.dat）：持久化已发现的 P2P 节点。
// ("addr", CAddress::GetKey()) -> CAddress；LoadAddresses 还会合并 addr.txt。
class CAddrDB : public CDB
{
public:
    CAddrDB(const char* pszMode="r+", bool fTxn=false) : CDB("addr.dat", pszMode, fTxn) { }
private:
    CAddrDB(const CAddrDB&);
    void operator=(const CAddrDB&);
public:
    bool WriteAddress(const CAddress& addr);
    bool LoadAddresses();
};

bool LoadAddresses();





// CWalletDB（wallet.dat）：钱包永久状态。
// 这里的内联方法同时更新对应内存映射（如 mapAddressBook）和磁盘记录。
class CWalletDB : public CDB
{
public:
    CWalletDB(const char* pszMode="r+", bool fTxn=false) : CDB("wallet.dat", pszMode, fTxn) { }
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);
public:
    // ("name", 可读地址字符串) -> 地址簿名称
    bool ReadName(const string& strAddress, string& strName)
    {
        strName = "";
        return Read(make_pair(string("name"), strAddress), strName);
    }

    bool WriteName(const string& strAddress, const string& strName)
    {
        mapAddressBook[strAddress] = strName;
        return Write(make_pair(string("name"), strAddress), strName);
    }

    bool EraseName(const string& strAddress)
    {
        mapAddressBook.erase(strAddress);
        return Erase(make_pair(string("name"), strAddress));
    }

    // ("tx", txid) -> 钱包交易及其本地元数据
    bool ReadTx(uint256 hash, CWalletTx& wtx)
    {
        return Read(make_pair(string("tx"), hash), wtx);
    }

    bool WriteTx(uint256 hash, const CWalletTx& wtx)
    {
        return Write(make_pair(string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash)
    {
        return Erase(make_pair(string("tx"), hash));
    }

    // ("key", 公钥字节) -> 私钥；写入禁止覆盖，避免意外替换密钥材料
    bool ReadKey(const vector<unsigned char>& vchPubKey, CPrivKey& vchPrivKey)
    {
        vchPrivKey.clear();
        return Read(make_pair(string("key"), vchPubKey), vchPrivKey);
    }

    bool WriteKey(const vector<unsigned char>& vchPubKey, const CPrivKey& vchPrivKey)
    {
        return Write(make_pair(string("key"), vchPubKey), vchPrivKey, false);
    }

    // "defaultkey" -> 启动时选作 keyUser 的公钥
    bool ReadDefaultKey(vector<unsigned char>& vchPubKey)
    {
        vchPubKey.clear();
        return Read(string("defaultkey"), vchPubKey);
    }

    bool WriteDefaultKey(const vector<unsigned char>& vchPubKey)
    {
        return Write(string("defaultkey"), vchPubKey);
    }

    // ("setting", 设置名) -> 设置值；此版本只在加载时识别少数固定名称
    template<typename T>
    bool ReadSetting(const string& strKey, T& value)
    {
        return Read(make_pair(string("setting"), strKey), value);
    }

    template<typename T>
    bool WriteSetting(const string& strKey, const T& value)
    {
        return Write(make_pair(string("setting"), strKey), value);
    }

    // 全表扫描 wallet.dat，将记录分派到地址簿、交易、密钥和设置等内存状态。
    bool LoadWallet(vector<unsigned char>& vchDefaultKeyRet);
};

// 高层启动入口：加载钱包；若没有有效默认密钥则创建并持久化新密钥。
bool LoadWallet();

inline bool SetAddressBookName(const string& strAddress, const string& strName)
{
    return CWalletDB().WriteName(strAddress, strName);
}
