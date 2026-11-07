// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// util.cpp — 通用工具的进程级实现
//=============================================================================
//
// 【本文件功能】
//   实现 util.h 中的随机源初始化、格式化与错误报告、金额解析、文件工具、
//   无偏随机数，以及根据对等节点样本校正本地网络时间。
//
// 【在整个系统中的作用】
//   本文件在进程启动时配置旧版 OpenSSL 的线程锁并播种 PRNG；运行期间为钱包、
//   网络和界面模块提供共同的系统服务。这里的时间偏移会影响节点使用的“当前时间”。
//
// 【阅读提示】
//   CInit 的全局实例在 main 之前构造、退出时析构。金额内部单位由 main.h 的
//   CENT 等常量决定；ParseMoney/FormatMoney 处理的是早期客户端的两位小数界面。
//
//=============================================================================

#include "headers.h"



// 进程级调试开关，供各模块共享。
bool fDebug = false;




// Init openssl library multithreading support
// OpenSSL 0.9.x 需要应用程序提供静态锁回调；每个锁编号对应一个 Win32 mutex。
static HANDLE* lock_cs;

// OpenSSL 在进入/离开其内部共享结构时调用的加锁回调。
void win32_locking_callback(int mode, int type, const char* file, int line)
{
    if (mode & CRYPTO_LOCK)
        WaitForSingleObject(lock_cs[type], INFINITE);
    else
        ReleaseMutex(lock_cs[type]);
}

// Init
// 进程生命周期初始化器：安装 OpenSSL 锁，收集系统熵；析构时反向释放。
class CInit
{
public:
    CInit()
    {
        // Init openssl library multithreading support
        lock_cs = (HANDLE*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            lock_cs[i] = CreateMutex(NULL,FALSE,NULL);
        CRYPTO_set_locking_callback(win32_locking_callback);

        // Seed random number generator with screen scrape and other hardware sources
        RAND_screen();

        // Seed random number generator with perfmon data
        RandAddSeed(true);
    }
    ~CInit()
    {
        // Shutdown openssl library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i =0 ; i < CRYPTO_num_locks(); i++)
            CloseHandle(lock_cs[i]);
        OPENSSL_free(lock_cs);
    }
}
instance_of_cinit;




// 始终混入高精度计数器；首次或每隔五分钟还可混入 Windows 性能注册表数据。
void RandAddSeed(bool fPerfmon)
{
    // Seed with CPU performance counter
    LARGE_INTEGER PerformanceCount;
    QueryPerformanceCounter(&PerformanceCount);
    RAND_add(&PerformanceCount, sizeof(PerformanceCount), 1.5);
    memset(&PerformanceCount, 0, sizeof(PerformanceCount));

    static int64 nLastPerfmon;
    if (fPerfmon || GetTime() > nLastPerfmon + 5 * 60)
    {
        nLastPerfmon = GetTime();

        // Seed with the entire set of perfmon data
        unsigned char pdata[250000];
        memset(pdata, 0, sizeof(pdata));
        unsigned long nSize = sizeof(pdata);
        long ret = RegQueryValueEx(HKEY_PERFORMANCE_DATA, "Global", NULL, NULL, pdata, &nSize);
        RegCloseKey(HKEY_PERFORMANCE_DATA);
        if (ret == ERROR_SUCCESS)
        {
            uint256 hash;
            SHA256(pdata, nSize, (unsigned char*)&hash);
            RAND_add(&hash, sizeof(hash), min(nSize/500.0, (double)sizeof(hash)));
            hash = 0;
            memset(pdata, 0, nSize);

            time_t nTime;
            time(&nTime);
            struct tm* ptmTime = gmtime(&nTime);
            char pszTime[200];
            strftime(pszTime, sizeof(pszTime), "%x %H:%M:%S", ptmTime);
            printf("%s  RandAddSeed() got %d bytes of performance data\n", pszTime, nSize);
        }
    }
}










// Safer snprintf
//  - prints up to limit-1 characters
//  - output string is always null terminated even if limit reached
//  - return value is the number of characters actually printed
// 与旧版 _vsnprintf 不同，本包装保证目标缓冲区以 NUL 结尾。
int my_snprintf(char* buffer, size_t limit, const char* format, ...)
{
    if (limit == 0)
        return 0;
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnprintf(buffer, limit, format, arg_ptr);
    va_end(arg_ptr);
    if (ret < 0 || ret >= limit)
    {
        ret = limit - 1;
        buffer[limit-1] = 0;
    }
    return ret;
}


// printf 风格生成 std::string；固定栈缓冲不足时逐倍扩容。
string strprintf(const char* format, ...)
{
    char buffer[50000];
    char* p = buffer;
    int limit = sizeof(buffer);
    int ret;
    loop
    {
        va_list arg_ptr;
        va_start(arg_ptr, format);
        ret = _vsnprintf(p, limit, format, arg_ptr);
        va_end(arg_ptr);
        if (ret >= 0 && ret < limit)
            break;
        if (p != buffer)
            delete p;
        limit *= 2;
        p = new char[limit];
        if (p == NULL)
            throw std::bad_alloc();
    }
#ifdef _MSC_VER
    // msvc optimisation
    if (p == buffer)
        return string(p, p+ret);
#endif
    string str(p, p+ret);
    if (p != buffer)
        delete p;
    return str;
}


// 统一输出带 ERROR 前缀的消息并返回 false，便于错误路径直接返回。
bool error(const char* format, ...)
{
    char buffer[50000];
    int limit = sizeof(buffer);
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnprintf(buffer, limit, format, arg_ptr);
    va_end(arg_ptr);
    if (ret < 0 || ret >= limit)
    {
        ret = limit - 1;
        buffer[limit-1] = 0;
    }
    printf("ERROR: %s\n", buffer);
    return false;
}


// 打印异常上下文；GUI 存在时弹出错误框，随后重新抛出当前异常。
void PrintException(std::exception* pex, const char* pszThread)
{
    char pszModule[260];
    pszModule[0] = '\0';
    GetModuleFileName(NULL, pszModule, sizeof(pszModule));
    _strlwr(pszModule);
    char pszMessage[1000];
    if (pex)
        snprintf(pszMessage, sizeof(pszMessage),
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        snprintf(pszMessage, sizeof(pszMessage),
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
    printf("\n\n************************\n%s", pszMessage);
    if (wxTheApp)
        wxMessageBox(pszMessage, "Error", wxOK | wxICON_ERROR);
    throw;
    //DebugBreak();
}


// 按单个分隔字符切分，并保留空字段。
void ParseString(const string& str, char c, vector<string>& v)
{
    unsigned int i1 = 0;
    unsigned int i2;
    do
    {
        i2 = str.find(c, i1);
        v.push_back(str.substr(i1, i2-i1));
        i1 = i2+1;
    }
    while (i2 != str.npos);
}


// 把最小货币单位转换为带千位分隔和两位小数的界面字符串。
string FormatMoney(int64 n, bool fPlus)
{
    n /= CENT;
    string str = strprintf("%I64d.%02I64d", (n > 0 ? n : -n)/100, (n > 0 ? n : -n)%100);
    for (int i = 6; i < str.size(); i += 4)
        if (isdigit(str[str.size() - i - 1]))
            str.insert(str.size() - i, 1, ',');
    if (n < 0)
        str.insert((unsigned int)0, 1, '-');
    else if (fPlus && n > 0)
        str.insert((unsigned int)0, 1, '+');
    return str;
}

// 严格解析非负金额：允许规范千位逗号和恰好两位小数，并检查溢出。
bool ParseMoney(const char* pszIn, int64& nRet)
{
    string strWhole;
    int64 nCents = 0;
    const char* p = pszIn;
    while (isspace(*p))
        p++;
    for (; *p; p++)
    {
        if (*p == ',' && p > pszIn && isdigit(p[-1]) && isdigit(p[1]) && isdigit(p[2]) && isdigit(p[3]) && !isdigit(p[4]))
            continue;
        if (*p == '.')
        {
            p++;
            if (!isdigit(p[0]) || !isdigit(p[1]))
                return false;
            nCents = atoi64(p);
            if (nCents < 0 || nCents > 99)
                return false;
            p += 2;
            break;
        }
        if (isspace(*p))
            break;
        if (!isdigit(*p))
            return false;
        strWhole.insert(strWhole.end(), *p);
    }
    for (; *p; p++)
        if (!isspace(*p))
            return false;
    if (strWhole.size() > 17)
        return false;
    int64 nWhole = atoi64(strWhole);
    int64 nValue = nWhole * 100 + nCents;
    if (nValue / 100 != nWhole)
        return false;
    nValue *= CENT;
    nRet = nValue;
    return true;
}










// 轻量文件存在性检查。
bool FileExists(const char* psz)
{
#ifdef WIN32
    return GetFileAttributes(psz) != -1;
#else
    return access(psz, 0) != -1;
#endif
}

// 暂存当前位置，跳到文件尾测量长度，再恢复原位置。
int GetFilesize(FILE* file)
{
    int nSavePos = ftell(file);
    int nFilesize = -1;
    if (fseek(file, 0, SEEK_END) == 0)
        nFilesize = ftell(file);
    fseek(file, nSavePos, SEEK_SET);
    return nFilesize;
}








// 返回 [0,nMax) 的密码学随机整数；拒绝采样消除直接取模造成的分布偏差。
uint64 GetRand(uint64 nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64 nRange = (_UI64_MAX / nMax) * nMax;
    uint64 nRand = 0;
    do
        RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
    while (nRand >= nRange);
    return (nRand % nMax);
}










//
// "Never go to sea with two chronometers; take one or three."
// Our three chronometers are:
//  - System clock
//  - Median of other server's clocks
//  - NTP servers
//
// note: NTP isn't implemented yet, so until then we just use the median
//  of other nodes clocks to correct ours.
//

// 未校正的系统 Unix 时间。
int64 GetTime()
{
    return time(NULL);
}

// 对等节点样本计算出的中位数偏移，仅作用于 GetAdjustedTime。
static int64 nTimeOffset = 0;

// 节点业务使用的当前时间：系统时间加网络中位数偏移。
int64 GetAdjustedTime()
{
    return GetTime() + nTimeOffset;
}

// 每个 IP 只采一个时间差；样本数达到至少 5 个奇数时更新中位数偏移。
void AddTimeData(unsigned int ip, int64 nTime)
{
    int64 nOffsetSample = nTime - GetTime();

    // Ignore duplicates
    static set<unsigned int> setKnown;
    if (!setKnown.insert(ip).second)
        return;

    // Add data
    static vector<int64> vTimeOffsets;
    if (vTimeOffsets.empty())
        vTimeOffsets.push_back(0);
    vTimeOffsets.push_back(nOffsetSample);
    printf("Added time data, samples %d, ip %08x, offset %+I64d (%+I64d minutes)\n", vTimeOffsets.size(), ip, vTimeOffsets.back(), vTimeOffsets.back()/60);
    if (vTimeOffsets.size() >= 5 && vTimeOffsets.size() % 2 == 1)
    {
        sort(vTimeOffsets.begin(), vTimeOffsets.end());
        int64 nMedian = vTimeOffsets[vTimeOffsets.size()/2];
        nTimeOffset = nMedian;
        if ((nMedian > 0 ? nMedian : -nMedian) > 5 * 60)
        {
            // Only let other nodes change our clock so far before we
            // go to the NTP servers
            /// todo: Get time from NTP servers, then set a flag
            ///    to make sure it doesn't get changed again
        }
        foreach(int64 n, vTimeOffsets)
            printf("%+I64d  ", n);
        printf("|  nTimeOffset = %+I64d  (%+I64d minutes)\n", nTimeOffset, nTimeOffset/60);
    }
}
