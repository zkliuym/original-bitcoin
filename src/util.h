// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// util.h — 全局基础工具、同步原语与哈希辅助
//=============================================================================
//
// 【本文件功能】
//   汇集早期客户端共用的类型/内存宏、字符串与金额处理、随机数、时间校正、
//   Windows 临界区 RAII、调试输出，以及 Bitcoin 常用哈希组合。
//
// 【在整个系统中的作用】
//   几乎所有模块都通过本文件获得基础设施：网络线程同步、钱包金额显示与解析、
//   OpenSSL 随机源、节点时间、对象哈希和地址所需的 Hash160。
//
// 【阅读提示】
//   这是旧代码中的“大工具箱”，声明与模板在本文件，非模板实现见 util.cpp。
//   Hash 是双 SHA256；Hash160 是 RIPEMD160(SHA256(x))。二者用途不同。
//
//=============================================================================


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

#ifndef _MSC_VER
#define __forceinline  inline
#endif

// 常用语法与对象连续内存边界宏；UBEGIN/UEND 常用于固定宽度哈希值。
#define foreach             BOOST_FOREACH
#define loop                for (;;)
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

#ifdef _WINDOWS
#define printf              OutputDebugStringF
#endif

#ifdef snprintf
#undef snprintf
#endif
#define snprintf my_snprintf

#ifndef PRId64
#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__MSVCRT__)
#define PRId64  "I64d"
#define PRIu64  "I64u"
#define PRIx64  "I64x"
#else
#define PRId64  "lld"
#define PRIu64  "llu"
#define PRIx64  "llx"
#endif
#endif

// This is needed because the foreach macro can't get over the comma in pair<t1, t2>
#define PAIRTYPE(t1, t2)    pair<t1, t2>

// Used to bypass the rule against non-const reference to temporary
// where it makes sense with wrappers such as CFlatData or CTxDB
template<typename T>
inline T& REF(const T& val)
{
    return (T&)val;
}









// 全局调试开关；开启后部分路径会输出更多诊断信息。
extern bool fDebug;

// 为 OpenSSL PRNG 混入性能计数器及可选的系统性能数据。
void RandAddSeed(bool fPerfmon=false);
// 安全截断且保证 NUL 结尾的 snprintf 包装，以及动态长度格式化字符串。
int my_snprintf(char* buffer, size_t limit, const char* format, ...);
string strprintf(const char* format, ...);
// 记录错误并固定返回 false，方便直接写成 return error(...)。
bool error(const char* format, ...);
// 统一记录线程异常、弹窗并重新抛出。
void PrintException(std::exception* pex, const char* pszThread);
// 字符串拆分及钱包金额的显示/严格解析。
void ParseString(const string& str, char c, vector<string>& v);
string FormatMoney(int64 n, bool fPlus=false);
bool ParseMoney(const char* pszIn, int64& nRet);
// 文件、随机数及本地/网络校正时间工具。
bool FileExists(const char* psz);
int GetFilesize(FILE* file);
uint64 GetRand(uint64 nMax);
int64 GetTime();
int64 GetAdjustedTime();
void AddTimeData(unsigned int ip, int64 nTime);












// Wrapper to automatically initialize critical section
// Could use wxCriticalSection for portability, but it doesn't support TryEnterCriticalSection
// Windows CRITICAL_SECTION 的拥有者，自动初始化/销毁，并记录当前加锁位置供调试。
class CCriticalSection
{
protected:
    CRITICAL_SECTION cs;
public:
    char* pszFile;
    int nLine;
    explicit CCriticalSection() { InitializeCriticalSection(&cs); }
    ~CCriticalSection() { DeleteCriticalSection(&cs); }
    void Enter() { EnterCriticalSection(&cs); }
    void Leave() { LeaveCriticalSection(&cs); }
    bool TryEnter() { return TryEnterCriticalSection(&cs); }
    CRITICAL_SECTION* operator&() { return &cs; }
};

// Automatically leave critical section when leaving block, needed for exception safety
// 作用域锁：构造即加锁，离开代码块（包括异常路径）自动解锁。
class CCriticalBlock
{
protected:
    CRITICAL_SECTION* pcs;
public:
    CCriticalBlock(CRITICAL_SECTION& csIn) { pcs = &csIn; EnterCriticalSection(pcs); }
    CCriticalBlock(CCriticalSection& csIn) { pcs = &csIn; EnterCriticalSection(pcs); }
    ~CCriticalBlock() { LeaveCriticalSection(pcs); }
};

// WARNING: This will catch continue and break!
// break is caught with an assertion, but there's no way to detect continue.
// I'd rather be careful than suffer the other more error prone syntax.
// The compiler will optimise away all this loop junk.
// 把“作用域锁”包装成代码块语法；不要在块内使用 continue，break 也会触发断言。
#define CRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by CRITICAL_BLOCK!", !fcriticalblockonce)), fcriticalblockonce=false)  \
    for (CCriticalBlock criticalblock(cs); fcriticalblockonce && (cs.pszFile=__FILE__, cs.nLine=__LINE__, true); fcriticalblockonce=false, cs.pszFile=NULL, cs.nLine=0)

// 非阻塞作用域锁；Entered() 表示本次 TryEnter 是否成功。
class CTryCriticalBlock
{
protected:
    CRITICAL_SECTION* pcs;
public:
    CTryCriticalBlock(CRITICAL_SECTION& csIn) { pcs = (TryEnterCriticalSection(&csIn) ? &csIn : NULL); }
    CTryCriticalBlock(CCriticalSection& csIn) { pcs = (TryEnterCriticalSection(&csIn) ? &csIn : NULL); }
    ~CTryCriticalBlock() { if (pcs) LeaveCriticalSection(pcs); }
    bool Entered() { return pcs != NULL; }
};

#define TRY_CRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by TRY_CRITICAL_BLOCK!", !fcriticalblockonce)), fcriticalblockonce=false)  \
    for (CTryCriticalBlock criticalblock(cs); fcriticalblockonce && (fcriticalblockonce = criticalblock.Entered()) && (cs.pszFile=__FILE__, cs.nLine=__LINE__, true); fcriticalblockonce=false, cs.pszFile=NULL, cs.nLine=0)












inline string i64tostr(int64 n)
{
    return strprintf("%"PRId64, n);
}

inline string itostr(int n)
{
    return strprintf("%d", n);
}

inline int64 atoi64(const char* psz)
{
#ifdef _MSC_VER
    return _atoi64(psz);
#else
    return strtoll(psz, NULL, 10);
#endif
}

inline int64 atoi64(const string& str)
{
#ifdef _MSC_VER
    return _atoi64(str.c_str());
#else
    return strtoll(str.c_str(), NULL, 10);
#endif
}

inline int atoi(const string& str)
{
    return atoi(str.c_str());
}

inline int roundint(double d)
{
    return (int)(d > 0 ? d + 0.5 : d - 0.5);
}

// 将连续元素按内存顺序显示为十六进制字节串。
template<typename T>
string HexStr(const T itbegin, const T itend, bool fSpaces=true)
{
    const unsigned char* pbegin = (const unsigned char*)&itbegin[0];
    const unsigned char* pend = pbegin + (itend - itbegin) * sizeof(itbegin[0]);
    string str;
    for (const unsigned char* p = pbegin; p != pend; p++)
        str += strprintf((fSpaces && p != pend-1 ? "%02x " : "%02x"), *p);
    return str;
}

template<typename T>
string HexNumStr(const T itbegin, const T itend, bool f0x=true)
{
    const unsigned char* pbegin = (const unsigned char*)&itbegin[0];
    const unsigned char* pend = pbegin + (itend - itbegin) * sizeof(itbegin[0]);
    string str = (f0x ? "0x" : "");
    for (const unsigned char* p = pend-1; p >= pbegin; p--)
        str += strprintf("%02X", *p);
    return str;
}

template<typename T>
void PrintHex(const T pbegin, const T pend, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(pbegin, pend, fSpaces).c_str());
}








// Windows 调试输出入口：调试构建按行写 debug.log/调试器，否则可退回控制台。
inline int OutputDebugStringF(const char* pszFormat, ...)
{
#ifdef __WXDEBUG__
    // log file
    FILE* fileout = fopen("debug.log", "a");
    if (fileout)
    {
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        vfprintf(fileout, pszFormat, arg_ptr);
        va_end(arg_ptr);
        fclose(fileout);
    }

    // accumulate a line at a time
    static CCriticalSection cs_OutputDebugStringF;
    CRITICAL_BLOCK(cs_OutputDebugStringF)
    {
        static char pszBuffer[50000];
        static char* pend;
        if (pend == NULL)
            pend = pszBuffer;
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        int limit = END(pszBuffer) - pend - 2;
        int ret = _vsnprintf(pend, limit, pszFormat, arg_ptr);
        va_end(arg_ptr);
        if (ret < 0 || ret >= limit)
        {
            pend = END(pszBuffer) - 2;
            *pend++ = '\n';
        }
        else
            pend += ret;
        *pend = '\0';
        char* p1 = pszBuffer;
        char* p2;
        while (p2 = strchr(p1, '\n'))
        {
            p2++;
            char c = *p2;
            *p2 = '\0';
            OutputDebugString(p1);
            *p2 = c;
            p1 = p2;
        }
        if (p1 != pszBuffer)
            memmove(pszBuffer, p1, pend - p1 + 1);
        pend -= (p1 - pszBuffer);
        return ret;
    }
#endif

    if (!wxTheApp)
    {
        // print to console
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        vprintf(pszFormat, arg_ptr);
        va_end(arg_ptr);
    }
    return 0;
}









inline void heapchk()
{
    if (_heapchk() != _HEAPOK)
        DebugBreak();
}

// Randomize the stack to help protect against buffer overrun exploits
// 以随机递归深度扰动线程入口栈布局，是早期代码中的缓冲区溢出缓解措施。
#define IMPLEMENT_RANDOMIZE_STACK(ThreadFn)                         \
    {                                                               \
        static char nLoops;                                         \
        if (nLoops <= 0)                                            \
            nLoops = GetRand(50) + 1;                               \
        if (nLoops-- > 1)                                           \
        {                                                           \
            ThreadFn;                                               \
            return;                                                 \
        }                                                           \
    }

#define CATCH_PRINT_EXCEPTION(pszFn)     \
    catch (std::exception& e) {          \
        PrintException(&e, (pszFn));     \
    } catch (...) {                      \
        PrintException(NULL, (pszFn));   \
    }









// 对一段连续数据执行两次 SHA256；交易 ID、区块哈希等广泛使用该约定。
template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    uint256 hash1;
    SHA256((unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx, (unsigned char*)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

// 按指定序列化场景编码对象，再对所得字节做双 SHA256。
template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=VERSION)
{
    // Most of the time is spent allocating and deallocating CDataStream's
    // buffer.  If this ever needs to be optimized further, make a CStaticStream
    // class with its buffer on the stack.
    CDataStream ss(nType, nVersion);
    ss.reserve(10000);
    ss << obj;
    return Hash(ss.begin(), ss.end());
}

// 公钥标识常用组合：RIPEMD160(SHA256(data))，输出固定 160 位摘要。
inline uint160 Hash160(const vector<unsigned char>& vch)
{
    uint256 hash1;
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}
