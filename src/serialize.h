// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// serialize.h — Bitcoin v0.1.3 通用序列化框架
//=============================================================================
//
// 【本文件功能】
//   把任意 C++ 对象编码成字节流（Serialize），或从字节流还原（Unserialize），
//   并可在不真正写出的情况下预先计算编码长度（GetSerializeSize）。
//   同一套模板/宏服务于：网络消息、磁盘文件、对象哈希（txid / 块哈希等）。
//
// 【在整个系统中的作用】
//   1. 网络层（net / main ProcessMessage）
//      - CNode 收发缓冲区是 CDataStream；P2P 的 version/tx/block/addr 等
//        都通过 operator<< / >> 编解码。节点间字节布局由本文件约定。
//   2. 共识与哈希（main / script）
//      - 交易哈希、块头哈希、SignatureHash 等先把对象序列化到流（常配合
//        SER_GETHASH），再对该字节做双重 SHA256。布局变了哈希就变，属共识。
//   3. 磁盘持久化（db / blk*.dat）
//      - CAutoFile 包装 FILE*，块数据、CTxIndex、钱包记录等以 SER_DISK
//        写入 Berkeley DB 或 blkNNNN.dat。
//   4. 业务类型接入方式
//      - CTransaction、CBlock、CAddress 等在各自头文件里用 IMPLEMENT_SERIALIZE
//        + READWRITE 声明字段列表；本文件提供底层原语与容器特化。
//
// 【核心设计】
//   - 面向“像流”的对象：只要有 read(char*,int) / write(char*,int) 即可。
//   - nType：场景标志（网络 / 磁盘 / 取哈希，以及 SKIPSIG、HEADERONLY 等修饰）。
//   - nVersion：协议/软件版本，默认 VERSION=103（即 0.1.3）；可与对端协商
//     取较小值，以便向前兼容字段布局。
//   - 基础类型按本机内存布局直写（x86 上为小端）；字符串/容器前缀 CompactSize。
//
// 【阅读提示】
//   自定义类型 → 搜 IMPLEMENT_SERIALIZE
//   收发包     → CDataStream
//   读写块文件 → CAutoFile
//   长度前缀   → WriteCompactSize / ReadCompactSize
//
//=============================================================================

#include <vector>
#include <map>
#include <boost/type_traits/is_fundamental.hpp>
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64  int64;
typedef unsigned __int64  uint64;
#else
typedef long long  int64;
typedef unsigned long long  uint64;
#endif
#if defined(_MSC_VER) && _MSC_VER < 1300
#define for  if (false) ; else for
#endif
class CScript;
class CDataStream;
class CAutoFile;

// 本客户端协议/软件版本号 0.1.3（1*100+0*10+3 的整数写法为 103）。
// 用途：version 消息、流默认 nVersion、新建 DB 时写入的 "version" 记录；
// 与交易/区块头里的 nVersion=1 不是同一概念。
static const int VERSION = 103;





/////////////////////////////////////////////////////////////////
//
// Templates for serializing to anything that looks like a stream,
// i.e. anything that supports .read(char*, int) and .write(char*, int)
//
// 序列化场景标志（nType）：可按位组合。
// 业务类的 IMPLEMENT_SERIALIZE 里可根据 nType 决定是否写出某字段
// （例如 SER_BLOCKHEADERONLY 时 CBlock 只写块头、不写交易列表）。
//

enum
{
    // 主场景
    SER_NETWORK         = (1 << 0),  // 对等网络消息编解码
    SER_DISK            = (1 << 1),  // 落盘（blk*.dat / Berkeley DB 记录）
    SER_GETHASH         = (1 << 2),  // 仅为计算哈希而序列化（如 GetHash）

    // 修饰标志（与主场景组合使用）
    SER_SKIPSIG         = (1 << 16), // 跳过签名相关字段（旧逻辑/特殊哈希用）
    SER_BLOCKHEADERONLY = (1 << 17), // 只序列化块头（给非 NODE_NETWORK 的轻客户端）
};

// 为自定义类型一次性生成三个成员：
//   GetSerializeSize / Serialize / Unserialize
// statements 里写一连串 READWRITE(字段)；同一份字段列表同时服务“算长/写/读”，
// 避免三处手写不一致。CTransaction、CBlock、CInv 等均依赖此宏接入本框架。
#define IMPLEMENT_SERIALIZE(statements)    \
    unsigned int GetSerializeSize(int nType=0, int nVersion=VERSION) const  \
    {                                           \
        CSerActionGetSerializeSize ser_action;  \
        const bool fGetSize = true;             \
        const bool fWrite = false;              \
        const bool fRead = false;               \
        unsigned int nSerSize = 0;              \
        ser_streamplaceholder s;                \
        s.nType = nType;                        \
        s.nVersion = nVersion;                  \
        {statements}                            \
        return nSerSize;                        \
    }                                           \
    template<typename Stream>                   \
    void Serialize(Stream& s, int nType=0, int nVersion=VERSION) const  \
    {                                           \
        CSerActionSerialize ser_action;         \
        const bool fGetSize = false;            \
        const bool fWrite = true;               \
        const bool fRead = false;               \
        unsigned int nSerSize = 0;              \
        {statements}                            \
    }                                           \
    template<typename Stream>                   \
    void Unserialize(Stream& s, int nType=0, int nVersion=VERSION)  \
    {                                           \
        CSerActionUnserialize ser_action;       \
        const bool fGetSize = false;            \
        const bool fWrite = false;              \
        const bool fRead = true;                \
        unsigned int nSerSize = 0;              \
        {statements}                            \
    }

// 在 IMPLEMENT_SERIALIZE 的 statements 中使用：按当前 ser_action
// 自动走“累加长度 / 写出 / 读入”之一。可配合 if (fRead) 等做条件字段。
#define READWRITE(obj)      (nSerSize += ::SerReadWrite(s, (obj), nType, nVersion, ser_action))






//
// Basic types — 基础类型：按内存字节原样读写（本机小端）。
// 系统作用：构成所有更复杂结构的字节基元；金额、高度、时间戳、nonce 等直接走这里。
//
#define WRITEDATA(s, obj)   s.write((char*)&(obj), sizeof(obj))
#define READDATA(s, obj)    s.read((char*)&(obj), sizeof(obj))

inline unsigned int GetSerializeSize(char a,           int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(signed char a,    int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(unsigned char a,  int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(signed short a,   int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(unsigned short a, int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(signed int a,     int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(unsigned int a,   int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(signed long a,    int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(unsigned long a,  int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(int64 a,          int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(uint64 a,         int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(float a,          int, int=0) { return sizeof(a); }
inline unsigned int GetSerializeSize(double a,         int, int=0) { return sizeof(a); }

template<typename Stream> inline void Serialize(Stream& s, char a,           int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, signed char a,    int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, unsigned char a,  int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, signed short a,   int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, unsigned short a, int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, signed int a,     int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, unsigned int a,   int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, signed long a,    int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, unsigned long a,  int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, int64 a,          int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, uint64 a,         int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, float a,          int, int=0) { WRITEDATA(s, a); }
template<typename Stream> inline void Serialize(Stream& s, double a,         int, int=0) { WRITEDATA(s, a); }

template<typename Stream> inline void Unserialize(Stream& s, char& a,           int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, signed char& a,    int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, unsigned char& a,  int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, signed short& a,   int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, unsigned short& a, int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, signed int& a,     int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, unsigned int& a,   int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, signed long& a,    int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, unsigned long& a,  int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, int64& a,          int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, uint64& a,         int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, float& a,          int, int=0) { READDATA(s, a); }
template<typename Stream> inline void Unserialize(Stream& s, double& a,         int, int=0) { READDATA(s, a); }

inline unsigned int GetSerializeSize(bool a, int, int=0)                          { return sizeof(char); }
template<typename Stream> inline void Serialize(Stream& s, bool a, int, int=0)    { char f=a; WRITEDATA(s, f); }
template<typename Stream> inline void Unserialize(Stream& s, bool& a, int, int=0) { char f; READDATA(s, f); a=f; }






//
// Compact size（可变长长度前缀，后世常称 CompactSize / VarInt 风格）
//  size <  253        -- 1 byte
//  size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
//  size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
//  size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)
//
// 系统作用：string / vector / map / set / CScript 等容器在线格式都以它开头，
// 既压缩小长度开销，又支持大集合。网络消息体与磁盘记录的容器字段都依赖此编码。
//
// 仅返回编码 nSize 本身需要的字节数（不含后续载荷）。
inline unsigned int GetSizeOfCompactSize(uint64 nSize)
{
    if (nSize < UCHAR_MAX-2)     return sizeof(unsigned char);
    else if (nSize <= USHRT_MAX) return sizeof(unsigned char) + sizeof(unsigned short);
    else if (nSize <= UINT_MAX)  return sizeof(unsigned char) + sizeof(unsigned int);
    else                         return sizeof(unsigned char) + sizeof(uint64);
}

// 把长度 nSize 按 CompactSize 规则写入流。
template<typename Stream>
void WriteCompactSize(Stream& os, uint64 nSize)
{
    if (nSize < UCHAR_MAX-2)
    {
        unsigned char chSize = nSize;
        WRITEDATA(os, chSize);
    }
    else if (nSize <= USHRT_MAX)
    {
        unsigned char chSize = UCHAR_MAX-2;
        unsigned short xSize = nSize;
        WRITEDATA(os, chSize);
        WRITEDATA(os, xSize);
    }
    else if (nSize <= UINT_MAX)
    {
        unsigned char chSize = UCHAR_MAX-1;
        unsigned int xSize = nSize;
        WRITEDATA(os, chSize);
        WRITEDATA(os, xSize);
    }
    else
    {
        unsigned char chSize = UCHAR_MAX;
        WRITEDATA(os, chSize);
        WRITEDATA(os, nSize);
    }
    return;
}

// 从流中读出一个 CompactSize，返回实际长度值。
template<typename Stream>
uint64 ReadCompactSize(Stream& is)
{
    unsigned char chSize;
    READDATA(is, chSize);
    if (chSize < UCHAR_MAX-2)
    {
        return chSize;
    }
    else if (chSize == UCHAR_MAX-2)
    {
        unsigned short nSize;
        READDATA(is, nSize);
        return nSize;
    }
    else if (chSize == UCHAR_MAX-1)
    {
        unsigned int nSize;
        READDATA(is, nSize);
        return nSize;
    }
    else
    {
        uint64 nSize;
        READDATA(is, nSize);
        return nSize;
    }
}



//
// Wrapper for serializing arrays and POD
// There's a clever template way to make arrays serialize normally, but MSVC6 doesn't support it
//
// CFlatData / FLATDATA：把一块连续内存（数组、POD）当作原始字节写出，不加 CompactSize。
// 系统中用于固定二进制块、C 风格数组等需要“原样拷贝”的字段。
//
#define FLATDATA(obj)   REF(CFlatData((char*)&(obj), (char*)&(obj) + sizeof(obj)))
class CFlatData
{
protected:
    char* pbegin;
    char* pend;
public:
    CFlatData(void* pbeginIn, void* pendIn) : pbegin((char*)pbeginIn), pend((char*)pendIn) { }
    char* begin() { return pbegin; }
    const char* begin() const { return pbegin; }
    char* end() { return pend; }
    const char* end() const { return pend; }

    unsigned int GetSerializeSize(int, int=0) const
    {
        return pend - pbegin;
    }

    template<typename Stream>
    void Serialize(Stream& s, int, int=0) const
    {
        s.write(pbegin, pend - pbegin);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int, int=0)
    {
        s.read(pbegin, pend - pbegin);
    }
};



//
// string stored as a fixed length field
// CFixedFieldString<LEN>：定长字符串槽（固定 LEN 字节），与带 CompactSize 的普通 string 不同。
//
template<std::size_t LEN>
class CFixedFieldString
{
protected:
    const string* pcstr;
    string* pstr;
public:
    explicit CFixedFieldString(const string& str) : pcstr(&str), pstr(NULL) { }
    explicit CFixedFieldString(string& str) : pcstr(&str), pstr(&str) { }

    unsigned int GetSerializeSize(int, int=0) const
    {
        return LEN;
    }

    template<typename Stream>
    void Serialize(Stream& s, int, int=0) const
    {
        char pszBuf[LEN];
        strncpy(pszBuf, pcstr->c_str(), LEN);
        s.write(pszBuf, LEN);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int, int=0)
    {
        if (pstr == NULL)
            throw std::ios_base::failure("CFixedFieldString::Unserialize : trying to unserialize to const string");
        char pszBuf[LEN+1];
        s.read(pszBuf, LEN);
        pszBuf[LEN] = '\0';
        *pstr = pszBuf;
    }
};





//
// Forward declarations — 标准库容器与 CScript 的序列化重载
//

// string：CompactSize(长度) + 原始字符
template<typename C> unsigned int GetSerializeSize(const basic_string<C>& str, int, int=0);
template<typename Stream, typename C> void Serialize(Stream& os, const basic_string<C>& str, int, int=0);
template<typename Stream, typename C> void Unserialize(Stream& is, basic_string<C>& str, int, int=0);

// vector：CompactSize + 元素；基础类型可整块 memcpy，复杂类型逐元素递归
template<typename T, typename A> unsigned int GetSerializeSize_impl(const std::vector<T, A>& v, int nType, int nVersion, const boost::true_type&);
template<typename T, typename A> unsigned int GetSerializeSize_impl(const std::vector<T, A>& v, int nType, int nVersion, const boost::false_type&);
template<typename T, typename A> inline unsigned int GetSerializeSize(const std::vector<T, A>& v, int nType, int nVersion=VERSION);
template<typename Stream, typename T, typename A> void Serialize_impl(Stream& os, const std::vector<T, A>& v, int nType, int nVersion, const boost::true_type&);
template<typename Stream, typename T, typename A> void Serialize_impl(Stream& os, const std::vector<T, A>& v, int nType, int nVersion, const boost::false_type&);
template<typename Stream, typename T, typename A> inline void Serialize(Stream& os, const std::vector<T, A>& v, int nType, int nVersion=VERSION);
template<typename Stream, typename T, typename A> void Unserialize_impl(Stream& is, std::vector<T, A>& v, int nType, int nVersion, const boost::true_type&);
template<typename Stream, typename T, typename A> void Unserialize_impl(Stream& is, std::vector<T, A>& v, int nType, int nVersion, const boost::false_type&);
template<typename Stream, typename T, typename A> inline void Unserialize(Stream& is, std::vector<T, A>& v, int nType, int nVersion=VERSION);

// CScript 当作 vector<unsigned char> 编解码（scriptSig / scriptPubKey）
extern inline unsigned int GetSerializeSize(const CScript& v, int nType, int nVersion=VERSION);
template<typename Stream> void Serialize(Stream& os, const CScript& v, int nType, int nVersion=VERSION);
template<typename Stream> void Unserialize(Stream& is, CScript& v, int nType, int nVersion=VERSION);

// pair：先 first 后 second（map 元素也走 pair）
template<typename K, typename T> unsigned int GetSerializeSize(const std::pair<K, T>& item, int nType, int nVersion=VERSION);
template<typename Stream, typename K, typename T> void Serialize(Stream& os, const std::pair<K, T>& item, int nType, int nVersion=VERSION);
template<typename Stream, typename K, typename T> void Unserialize(Stream& is, std::pair<K, T>& item, int nType, int nVersion=VERSION);

// map：CompactSize(个数) + 各 pair
template<typename K, typename T, typename Pred, typename A> unsigned int GetSerializeSize(const std::map<K, T, Pred, A>& m, int nType, int nVersion=VERSION);
template<typename Stream, typename K, typename T, typename Pred, typename A> void Serialize(Stream& os, const std::map<K, T, Pred, A>& m, int nType, int nVersion=VERSION);
template<typename Stream, typename K, typename T, typename Pred, typename A> void Unserialize(Stream& is, std::map<K, T, Pred, A>& m, int nType, int nVersion=VERSION);

// set：CompactSize(个数) + 各 key
template<typename K, typename Pred, typename A> unsigned int GetSerializeSize(const std::set<K, Pred, A>& m, int nType, int nVersion=VERSION);
template<typename Stream, typename K, typename Pred, typename A> void Serialize(Stream& os, const std::set<K, Pred, A>& m, int nType, int nVersion=VERSION);
template<typename Stream, typename K, typename Pred, typename A> void Unserialize(Stream& is, std::set<K, Pred, A>& m, int nType, int nVersion=VERSION);





//
// If none of the specialized versions above matched, default to calling member function.
// "int nType" is changed to "long nType" to keep from getting an ambiguous overload error.
// The compiler will only cast int to long if none of the other templates matched.
// Thanks to Boost serialization for this idea.
//
// 回落到类型成员（通常由 IMPLEMENT_SERIALIZE 生成）。
// 系统作用：CTransaction / CBlock / CAddress 等通过统一的 ::Serialize 入口被调用。
//
template<typename T>
inline unsigned int GetSerializeSize(const T& a, long nType, int nVersion=VERSION)
{
    return a.GetSerializeSize((int)nType, nVersion);
}

template<typename Stream, typename T>
inline void Serialize(Stream& os, const T& a, long nType, int nVersion=VERSION)
{
    a.Serialize(os, (int)nType, nVersion);
}

template<typename Stream, typename T>
inline void Unserialize(Stream& is, T& a, long nType, int nVersion=VERSION)
{
    a.Unserialize(is, (int)nType, nVersion);
}





//
// string — CompactSize(字符数) + 字符数据（标签、文本字段等）
//
template<typename C>
unsigned int GetSerializeSize(const basic_string<C>& str, int, int)
{
    return GetSizeOfCompactSize(str.size()) + str.size() * sizeof(str[0]);
}

template<typename Stream, typename C>
void Serialize(Stream& os, const basic_string<C>& str, int, int)
{
    WriteCompactSize(os, str.size());
    if (!str.empty())
        os.write((char*)&str[0], str.size() * sizeof(str[0]));
}

template<typename Stream, typename C>
void Unserialize(Stream& is, basic_string<C>& str, int, int)
{
    unsigned int nSize = ReadCompactSize(is);
    str.resize(nSize);
    if (nSize != 0)
        is.read((char*)&str[0], nSize * sizeof(str[0]));
}



//
// vector — vin/vout、vtx、脚本字节、inv 列表等大量使用
// true_type：T 为基础类型，整段裸写；false_type：对每个元素递归 Serialize
//
template<typename T, typename A>
unsigned int GetSerializeSize_impl(const std::vector<T, A>& v, int nType, int nVersion, const boost::true_type&)
{
    return (GetSizeOfCompactSize(v.size()) + v.size() * sizeof(T));
}

template<typename T, typename A>
unsigned int GetSerializeSize_impl(const std::vector<T, A>& v, int nType, int nVersion, const boost::false_type&)
{
    unsigned int nSize = GetSizeOfCompactSize(v.size());
    for (typename std::vector<T, A>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
        nSize += GetSerializeSize((*vi), nType, nVersion);
    return nSize;
}

template<typename T, typename A>
inline unsigned int GetSerializeSize(const std::vector<T, A>& v, int nType, int nVersion)
{
    return GetSerializeSize_impl(v, nType, nVersion, boost::is_fundamental<T>());
}


template<typename Stream, typename T, typename A>
void Serialize_impl(Stream& os, const std::vector<T, A>& v, int nType, int nVersion, const boost::true_type&)
{
    WriteCompactSize(os, v.size());
    if (!v.empty())
        os.write((char*)&v[0], v.size() * sizeof(T));
}

template<typename Stream, typename T, typename A>
void Serialize_impl(Stream& os, const std::vector<T, A>& v, int nType, int nVersion, const boost::false_type&)
{
    WriteCompactSize(os, v.size());
    for (typename std::vector<T, A>::const_iterator vi = v.begin(); vi != v.end(); ++vi)
        ::Serialize(os, (*vi), nType, nVersion);
}

template<typename Stream, typename T, typename A>
inline void Serialize(Stream& os, const std::vector<T, A>& v, int nType, int nVersion)
{
    Serialize_impl(os, v, nType, nVersion, boost::is_fundamental<T>());
}


template<typename Stream, typename T, typename A>
void Unserialize_impl(Stream& is, std::vector<T, A>& v, int nType, int nVersion, const boost::true_type&)
{
    //unsigned int nSize = ReadCompactSize(is);
    //v.resize(nSize);
    //is.read((char*)&v[0], nSize * sizeof(T));

    // 分块读取，避免恶意超大 size 一次性分配导致 OOM
    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    while (i < nSize)
    {
        unsigned int blk = min(nSize - i, 1 + 4999999 / sizeof(T));
        v.resize(i + blk);
        is.read((char*)&v[i], blk * sizeof(T));
        i += blk;
    }
}

template<typename Stream, typename T, typename A>
void Unserialize_impl(Stream& is, std::vector<T, A>& v, int nType, int nVersion, const boost::false_type&)
{
    //unsigned int nSize = ReadCompactSize(is);
    //v.resize(nSize);
    //for (std::vector<T, A>::iterator vi = v.begin(); vi != v.end(); ++vi)
    //    Unserialize(is, (*vi), nType, nVersion);

    v.clear();
    unsigned int nSize = ReadCompactSize(is);
    unsigned int i = 0;
    unsigned int nMid = 0;
    while (nMid < nSize)
    {
        nMid += 5000000 / sizeof(T);
        if (nMid > nSize)
            nMid = nSize;
        v.resize(nMid);
        for (; i < nMid; i++)
            Unserialize(is, v[i], nType, nVersion);
    }
}

template<typename Stream, typename T, typename A>
inline void Unserialize(Stream& is, std::vector<T, A>& v, int nType, int nVersion)
{
    Unserialize_impl(is, v, nType, nVersion, boost::is_fundamental<T>());
}



//
// others derived from vector — CScript 按字节向量处理
//
inline unsigned int GetSerializeSize(const CScript& v, int nType, int nVersion)
{
    return GetSerializeSize((const vector<unsigned char>&)v, nType, nVersion);
}

template<typename Stream>
void Serialize(Stream& os, const CScript& v, int nType, int nVersion)
{
    Serialize(os, (const vector<unsigned char>&)v, nType, nVersion);
}

template<typename Stream>
void Unserialize(Stream& is, CScript& v, int nType, int nVersion)
{
    Unserialize(is, (vector<unsigned char>&)v, nType, nVersion);
}



//
// pair — 顺序：first，再 second
//
template<typename K, typename T>
unsigned int GetSerializeSize(const std::pair<K, T>& item, int nType, int nVersion)
{
    return GetSerializeSize(item.first, nType, nVersion) + GetSerializeSize(item.second, nType, nVersion);
}

template<typename Stream, typename K, typename T>
void Serialize(Stream& os, const std::pair<K, T>& item, int nType, int nVersion)
{
    Serialize(os, item.first, nType, nVersion);
    Serialize(os, item.second, nType, nVersion);
}

template<typename Stream, typename K, typename T>
void Unserialize(Stream& is, std::pair<K, T>& item, int nType, int nVersion)
{
    Unserialize(is, item.first, nType, nVersion);
    Unserialize(is, item.second, nType, nVersion);
}



//
// map — CompactSize + 各 pair；钱包 mapValue、部分 DB/消息结构会用到
//
template<typename K, typename T, typename Pred, typename A>
unsigned int GetSerializeSize(const std::map<K, T, Pred, A>& m, int nType, int nVersion)
{
    unsigned int nSize = GetSizeOfCompactSize(m.size());
    for (typename std::map<K, T, Pred, A>::const_iterator mi = m.begin(); mi != m.end(); ++mi)
        nSize += GetSerializeSize((*mi), nType, nVersion);
    return nSize;
}

template<typename Stream, typename K, typename T, typename Pred, typename A>
void Serialize(Stream& os, const std::map<K, T, Pred, A>& m, int nType, int nVersion)
{
    WriteCompactSize(os, m.size());
    for (typename std::map<K, T, Pred, A>::const_iterator mi = m.begin(); mi != m.end(); ++mi)
        Serialize(os, (*mi), nType, nVersion);
}

template<typename Stream, typename K, typename T, typename Pred, typename A>
void Unserialize(Stream& is, std::map<K, T, Pred, A>& m, int nType, int nVersion)
{
    m.clear();
    unsigned int nSize = ReadCompactSize(is);
    typename std::map<K, T, Pred, A>::iterator mi = m.begin();
    for (unsigned int i = 0; i < nSize; i++)
    {
        pair<K, T> item;
        Unserialize(is, item, nType, nVersion);
        mi = m.insert(mi, item);
    }
}



//
// set — CompactSize + 各元素
//
template<typename K, typename Pred, typename A>
unsigned int GetSerializeSize(const std::set<K, Pred, A>& m, int nType, int nVersion)
{
    unsigned int nSize = GetSizeOfCompactSize(m.size());
    for (typename std::set<K, Pred, A>::const_iterator it = m.begin(); it != m.end(); ++it)
        nSize += GetSerializeSize((*it), nType, nVersion);
    return nSize;
}

template<typename Stream, typename K, typename Pred, typename A>
void Serialize(Stream& os, const std::set<K, Pred, A>& m, int nType, int nVersion)
{
    WriteCompactSize(os, m.size());
    for (typename std::set<K, Pred, A>::const_iterator it = m.begin(); it != m.end(); ++it)
        Serialize(os, (*it), nType, nVersion);
}

template<typename Stream, typename K, typename Pred, typename A>
void Unserialize(Stream& is, std::set<K, Pred, A>& m, int nType, int nVersion)
{
    m.clear();
    unsigned int nSize = ReadCompactSize(is);
    typename std::set<K, Pred, A>::iterator it = m.begin();
    for (unsigned int i = 0; i < nSize; i++)
    {
        K key;
        Unserialize(is, key, nType, nVersion);
        it = m.insert(it, key);
    }
}



//
// Support for IMPLEMENT_SERIALIZE and READWRITE macro
//
// 三个空标签类型区分“当前宏展开在干什么”；SerReadWrite 按标签分派到
// GetSerializeSize / Serialize / Unserialize。这样 READWRITE(x) 一份代码三种用途。
//
class CSerActionGetSerializeSize { }; // 只计算序列化后字节数
class CSerActionSerialize { };         // 写入流
class CSerActionUnserialize { };       // 从流读入

// 算长度：返回 obj 编码后的大小，累加到 nSerSize
template<typename Stream, typename T>
inline unsigned int SerReadWrite(Stream& s, const T& obj, int nType, int nVersion, CSerActionGetSerializeSize ser_action)
{
    return ::GetSerializeSize(obj, nType, nVersion);
}

// 写出：把 obj 写入流 s
template<typename Stream, typename T>
inline unsigned int SerReadWrite(Stream& s, const T& obj, int nType, int nVersion, CSerActionSerialize ser_action)
{
    ::Serialize(s, obj, nType, nVersion);
    return 0;
}

// 读入：从流 s 还原到 obj
template<typename Stream, typename T>
inline unsigned int SerReadWrite(Stream& s, T& obj, int nType, int nVersion, CSerActionUnserialize ser_action)
{
    ::Unserialize(s, obj, nType, nVersion);
    return 0;
}

// GetSerializeSize 路径里没有真实 Stream，用此占位符保存 nType/nVersion，
// 以便 statements 中仍可访问 s.nType / s.nVersion。
struct ser_streamplaceholder
{
    int nType;
    int nVersion;
};









//
// Allocator that clears its contents before deletion
//
// secure_allocator：释放内存前先 memset 清零，降低私钥等敏感数据残留在堆上的风险。
// 系统作用：CDataStream 底层 vector、以及 key 相关字节容器使用它存放可能含密钥的数据。
//
template<typename T>
struct secure_allocator : public std::allocator<T>
{
    // MSVC8 default copy constructor is broken
    typedef std::allocator<T> base;
    typedef typename base::size_type size_type;
    typedef typename base::difference_type  difference_type;
    typedef typename base::pointer pointer;
    typedef typename base::const_pointer const_pointer;
    typedef typename base::reference reference;
    typedef typename base::const_reference const_reference;
    typedef typename base::value_type value_type;
    secure_allocator() throw() {}
    secure_allocator(const secure_allocator& a) throw() : base(a) {}
    ~secure_allocator() throw() {}
    template<typename _Other> struct rebind
    { typedef secure_allocator<_Other> other; };

    void deallocate(T* p, std::size_t n)
    {
        if (p != NULL)
            memset(p, 0, sizeof(T) * n);
        allocator<T>::deallocate(p, n);
    }
};



//
// Double ended buffer combining vector and stream-like interfaces.
// >> and << read and write unformatted data using the above serialization templates.
// Fills with data in linear time; some stringstream implementations take N^2 time.
//
// CDataStream：内存中的可读写字节缓冲区 + 序列化流。
// 【系统中的核心载体】
//   - 每个 CNode 的 vSend / vRecv：拼装与解析 P2P 消息
//   - 计算 txid / 块哈希 / SignatureHash 时的临时缓冲（常配 SER_GETHASH）
//   - RelayMessage 缓存原始消息字节、钱包/DB 读写时的中间流等
// nReadPos 指向尚未消费的数据起点；<< 追加到末尾，>> / read 从 nReadPos 前进。
//
class CDataStream
{
protected:
    typedef vector<char, secure_allocator<char> > vector_type;
    vector_type vch;           // 底层字节存储（安全分配器）
    unsigned int nReadPos;     // 读指针：已消费数据的下一字节下标
    short state;               // iostream 风格状态位
    short exceptmask;          // 哪些状态位置位时抛异常
public:
    int nType;                 // 序列化场景（SER_NETWORK 等）
    int nVersion;              // 流协议版本（默认可为 VERSION=103）

    typedef vector_type::allocator_type   allocator_type;
    typedef vector_type::size_type        size_type;
    typedef vector_type::difference_type  difference_type;
    typedef vector_type::reference        reference;
    typedef vector_type::const_reference  const_reference;
    typedef vector_type::value_type       value_type;
    typedef vector_type::iterator         iterator;
    typedef vector_type::const_iterator   const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    // 空流；指定场景与版本
    explicit CDataStream(int nTypeIn=0, int nVersionIn=VERSION)
    {
        Init(nTypeIn, nVersionIn);
    }

    // 由一段已有字节构造（例如刚从 socket 剥出的 payload）
    CDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn=0, int nVersionIn=VERSION) : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    CDataStream(const char* pbegin, const char* pend, int nTypeIn=0, int nVersionIn=VERSION) : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }
#endif

    CDataStream(const vector_type& vchIn, int nTypeIn=0, int nVersionIn=VERSION) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const vector<char>& vchIn, int nTypeIn=0, int nVersionIn=VERSION) : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    CDataStream(const vector<unsigned char>& vchIn, int nTypeIn=0, int nVersionIn=VERSION) : vch((char*)&vchIn.begin()[0], (char*)&vchIn.end()[0])
    {
        Init(nTypeIn, nVersionIn);
    }

    // 重置读指针与流状态
    void Init(int nTypeIn=0, int nVersionIn=VERSION)
    {
        nReadPos = 0;
        nType = nTypeIn;
        nVersion = nVersionIn;
        state = 0;
        exceptmask = ios::badbit | ios::failbit;
    }

    // 拼接另一流中尚未读完的数据到本流末尾
    CDataStream& operator+=(const CDataStream& b)
    {
        vch.insert(vch.end(), b.begin(), b.end());
        return *this;
    }

    friend CDataStream operator+(const CDataStream& a, const CDataStream& b)
    {
        CDataStream ret = a;
        ret += b;
        return (ret);
    }

    // 未读区间转为 string（调试/少数文本用途）
    string str() const
    {
        return (string(begin(), end()));
    }


    //
    // Vector subset — 视图从 nReadPos 起，对外表现为“剩余未读缓冲”
    //
    const_iterator begin() const                     { return vch.begin() + nReadPos; }
    iterator begin()                                 { return vch.begin() + nReadPos; }
    const_iterator end() const                       { return vch.end(); }
    iterator end()                                   { return vch.end(); }
    size_type size() const                           { return vch.size() - nReadPos; }
    bool empty() const                               { return vch.size() == nReadPos; }
    void resize(size_type n, value_type c=0)         { vch.resize(n + nReadPos, c); }
    void reserve(size_type n)                        { vch.reserve(n + nReadPos); }
    const_reference operator[](size_type pos) const  { return vch[pos + nReadPos]; }
    reference operator[](size_type pos)              { return vch[pos + nReadPos]; }
    void clear()                                     { vch.clear(); nReadPos = 0; }
    iterator insert(iterator it, const char& x=char()) { return vch.insert(it, x); }
    void insert(iterator it, size_type n, const char& x) { vch.insert(it, n, x); }

    void insert(iterator it, const_iterator first, const_iterator last)
    {
        if (it == vch.begin() + nReadPos && last - first <= nReadPos)
        {
            // special case for inserting at the front when there's room
            nReadPos -= (last - first);
            memcpy(&vch[nReadPos], &first[0], last - first);
        }
        else
            vch.insert(it, first, last);
    }

#if !defined(_MSC_VER) || _MSC_VER >= 1300
    void insert(iterator it, const char* first, const char* last)
    {
        insert(it, (const_iterator)first, (const_iterator)last);
    }
#endif

    iterator erase(iterator it)
    {
        if (it == vch.begin() + nReadPos)
        {
            // special case for erasing from the front
            if (++nReadPos >= vch.size())
            {
                // whenever we reach the end, we take the opportunity to clear the buffer
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            return vch.begin() + nReadPos;
        }
        else
            return vch.erase(it);
    }

    iterator erase(iterator first, iterator last)
    {
        if (first == vch.begin() + nReadPos)
        {
            // special case for erasing from the front
            if (last == vch.end())
            {
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            else
            {
                nReadPos = (last - vch.begin());
                return last;
            }
        }
        else
            return vch.erase(first, last);
    }

    // 丢掉已读前缀，把未读数据移到缓冲区开头（回收内存）
    inline void Compact()
    {
        vch.erase(vch.begin(), vch.begin() + nReadPos);
        nReadPos = 0;
    }

    // 若尚未 Compact，可将读指针回退 n 字节（重新解析刚读过的数据）
    bool Rewind(size_type n)
    {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if (n > nReadPos)
            return false;
        nReadPos -= n;
        return true;
    }


    //
    // Stream subset — 模仿 iostream 接口，供 Serialize 模板的 read/write 调用
    //
    void setstate(short bits, const char* psz)
    {
        state |= bits;
        if (state & exceptmask)
            throw std::ios_base::failure(psz);
    }

    bool eof() const             { return size() == 0; }
    bool fail() const            { return state & (ios::badbit | ios::failbit); }
    bool good() const            { return !eof() && (state == 0); }
    void clear(short n)          { state = n; }  // name conflict with vector clear()
    short exceptions()           { return exceptmask; }
    short exceptions(short mask) { short prev = exceptmask; exceptmask = mask; setstate(0, "CDataStream"); return prev; }
    CDataStream* rdbuf()         { return this; }
    int in_avail()               { return size(); }

    void SetType(int n)          { nType = n; }
    int GetType()                { return nType; }
    void SetVersion(int n)       { nVersion = n; }   // 握手后常设为 min(本地, 对端)
    int GetVersion()             { return nVersion; }
    void ReadVersion()           { *this >> nVersion; }
    void WriteVersion()          { *this << nVersion; }

    // 从读指针拷贝 nSize 字节到 pch，并前进读指针；读尽则清空缓冲
    CDataStream& read(char* pch, int nSize)
    {
        // Read from the beginning of the buffer
        assert(nSize >= 0);
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size())
        {
            if (nReadPosNext > vch.size())
            {
                setstate(ios::failbit, "CDataStream::read() : end of data");
                memset(pch, 0, nSize);
                nSize = vch.size() - nReadPos;
            }
            memcpy(pch, &vch[nReadPos], nSize);
            nReadPos = 0;
            vch.clear();
            return (*this);
        }
        memcpy(pch, &vch[nReadPos], nSize);
        nReadPos = nReadPosNext;
        return (*this);
    }

    // 跳过 nSize 字节（不拷贝），用于跳过不关心的字段
    CDataStream& ignore(int nSize)
    {
        // Ignore from the beginning of the buffer
        assert(nSize >= 0);
        unsigned int nReadPosNext = nReadPos + nSize;
        if (nReadPosNext >= vch.size())
        {
            if (nReadPosNext > vch.size())
            {
                setstate(ios::failbit, "CDataStream::ignore() : end of data");
                nSize = vch.size() - nReadPos;
            }
            nReadPos = 0;
            vch.clear();
            return (*this);
        }
        nReadPos = nReadPosNext;
        return (*this);
    }

    // 在缓冲末尾追加原始字节（Serialize 基础类型最终落到这里）
    CDataStream& write(const char* pch, int nSize)
    {
        // Write to the end of the buffer
        assert(nSize >= 0);
        vch.insert(vch.end(), pch, pch + nSize);
        return (*this);
    }

    // 把本流整段内容当作字节写入另一流（流 << 流 即拼接）
    template<typename Stream>
    void Serialize(Stream& s, int nType=0, int nVersion=VERSION) const
    {
        // Special case: stream << stream concatenates like stream += stream
        if (!vch.empty())
            s.write((char*)&vch[0], vch.size() * sizeof(vch[0]));
    }

    // 若把 obj 按本流的 nType/nVersion 序列化，需要多少字节
    template<typename T>
    unsigned int GetSerializeSize(const T& obj)
    {
        // Tells the size of the object if serialized to this stream
        return ::GetSerializeSize(obj, nType, nVersion);
    }

    // 序列化写入：ss << tx; ss << block; 网络组包、算哈希前的编码都走这里
    template<typename T>
    CDataStream& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }

    // 反序列化读出：ss >> tx; 解析 P2P payload / 磁盘记录
    template<typename T>
    CDataStream& operator>>(T& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

#ifdef TESTCDATASTREAM
// VC6sp6
// CDataStream:
// n=1000       0 seconds
// n=2000       0 seconds
// n=4000       0 seconds
// n=8000       0 seconds
// n=16000      0 seconds
// n=32000      0 seconds
// n=64000      1 seconds
// n=128000     1 seconds
// n=256000     2 seconds
// n=512000     4 seconds
// n=1024000    8 seconds
// n=2048000    16 seconds
// n=4096000    32 seconds
// stringstream:
// n=1000       1 seconds
// n=2000       1 seconds
// n=4000       13 seconds
// n=8000       87 seconds
// n=16000      400 seconds
// n=32000      1660 seconds
// n=64000      6749 seconds
// n=128000     27241 seconds
// n=256000     109804 seconds
#include <iostream>
int main(int argc, char *argv[])
{
    vector<unsigned char> vch(0xcc, 250);
    printf("CDataStream:\n");
    for (int n = 1000; n <= 4500000; n *= 2)
    {
        CDataStream ss;
        time_t nStart = time(NULL);
        for (int i = 0; i < n; i++)
            ss.write((char*)&vch[0], vch.size());
        printf("n=%-10d %d seconds\n", n, time(NULL) - nStart);
    }
    printf("stringstream:\n");
    for (int n = 1000; n <= 4500000; n *= 2)
    {
        stringstream ss;
        time_t nStart = time(NULL);
        for (int i = 0; i < n; i++)
            ss.write((char*)&vch[0], vch.size());
        printf("n=%-10d %d seconds\n", n, time(NULL) - nStart);
    }
}
#endif










//
// Automatic closing wrapper for FILE*
//  - Will automatically close the file when it goes out of scope if not null.
//  - If you're returning the file pointer, return file.release().
//  - If you need to close the file early, use file.fclose() instead of fclose(file).
//
// CAutoFile：带 RAII 的 FILE* 包装，同时实现 read/write，故可直接作为序列化流。
// 【系统作用】
//   - 读写 blkNNNN.dat 中的原始区块（AppendBlockFile / ReadFromDisk）
//   - 默认 nType=SER_DISK，与网络路径的 CDataStream 对称：同一套 Serialize 逻辑，不同载体
//   - 析构自动 fclose；移交所有权用 release()，避免双重关闭
//
class CAutoFile
{
protected:
    FILE* file;
    short state;
    short exceptmask;
public:
    int nType;      // 通常为 SER_DISK
    int nVersion;   // 磁盘记录使用的序列化版本

    typedef FILE element_type;

    // 接管已打开的 FILE*；默认按磁盘场景序列化
    CAutoFile(FILE* filenew=NULL, int nTypeIn=SER_DISK, int nVersionIn=VERSION)
    {
        file = filenew;
        nType = nTypeIn;
        nVersion = nVersionIn;
        state = 0;
        exceptmask = ios::badbit | ios::failbit;
    }

    ~CAutoFile()
    {
        fclose();
    }

    // 显式关闭；忽略 stdin/stdout/stderr
    void fclose()
    {
        if (file != NULL && file != stdin && file != stdout && file != stderr)
            ::fclose(file);
        file = NULL;
    }

    FILE* release()             { FILE* ret = file; file = NULL; return ret; } // 交出所有权，不再自动关
    operator FILE*()            { return file; }
    FILE* operator->()          { return file; }
    FILE& operator*()           { return *file; }
    FILE** operator&()          { return &file; }
    FILE* operator=(FILE* pnew) { return file = pnew; }
    bool operator!()            { return (file == NULL); }


    //
    // Stream subset — 与 CDataStream 平行的文件版接口
    //
    void setstate(short bits, const char* psz)
    {
        state |= bits;
        if (state & exceptmask)
            throw std::ios_base::failure(psz);
    }

    bool fail() const            { return state & (ios::badbit | ios::failbit); }
    bool good() const            { return state == 0; }
    void clear(short n = 0)      { state = n; }
    short exceptions()           { return exceptmask; }
    short exceptions(short mask) { short prev = exceptmask; exceptmask = mask; setstate(0, "CAutoFile"); return prev; }

    void SetType(int n)          { nType = n; }
    int GetType()                { return nType; }
    void SetVersion(int n)       { nVersion = n; }
    int GetVersion()             { return nVersion; }
    void ReadVersion()           { *this >> nVersion; }
    void WriteVersion()          { *this << nVersion; }

    // 从文件读原始字节（Serialize 基础类型的底层）
    CAutoFile& read(char* pch, int nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::read : file handle is NULL");
        if (fread(pch, 1, nSize, file) != nSize)
            setstate(ios::failbit, feof(file) ? "CAutoFile::read : end of file" : "CAutoFile::read : fread failed");
        return (*this);
    }

    // 向文件写原始字节
    CAutoFile& write(const char* pch, int nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::write : file handle is NULL");
        if (fwrite(pch, 1, nSize, file) != nSize)
            setstate(ios::failbit, "CAutoFile::write : write failed");
        return (*this);
    }

    template<typename T>
    unsigned int GetSerializeSize(const T& obj)
    {
        // Tells the size of the object if serialized to this stream
        return ::GetSerializeSize(obj, nType, nVersion);
    }

    // 把对象按磁盘格式写入文件，例如 file << block;
    template<typename T>
    CAutoFile& operator<<(const T& obj)
    {
        // Serialize to this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator<< : file handle is NULL");
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }

    // 从文件按磁盘格式读出对象，例如 file >> block;
    template<typename T>
    CAutoFile& operator>>(T& obj)
    {
        // Unserialize from this stream
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator>> : file handle is NULL");
        ::Unserialize(*this, obj, nType, nVersion);
        return (*this);
    }
};
