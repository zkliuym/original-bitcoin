// This file is public domain
// SHA routines extracted as a standalone file from:
// Crypto++: a C++ Class Library of Cryptographic Schemes
// Version 5.5.2 (9/24/2007)
// http://www.cryptopp.com
//
//=============================================================================
// sha.h — 从 Crypto++ 提取的 SHA 压缩函数声明
//=============================================================================
//
// 【本文件功能】
//   定义基础字类型、固定位旋转、字节序反转，以及 SHA-1/SHA-224/SHA-256
//   （可选 SHA-384/SHA-512）的初始状态和单分组压缩接口。
//
// 【在整个系统中的作用】
//   这是独立的底层 SHA 原语，供需要直接处理压缩状态的代码使用；Bitcoin 主流程
//   中常见的整段 double-SHA256 仍主要通过 OpenSSL SHA256 API（见 util.h）完成。
//
// 【阅读提示】
//   Transform 只压缩一个已分组的数据块，不负责流式缓存、填充或输出编码。
//   本文件保留上游 Crypto++ 的平台优化与命名，阅读重点是各 SHA 类的两个静态接口。
//
//=============================================================================
#ifndef CRYPTOPP_SHA_H
#define CRYPTOPP_SHA_H
#include <stdlib.h>

namespace CryptoPP
{

//
// Dependencies
//

typedef unsigned char byte;
typedef unsigned short word16;
typedef unsigned int word32;
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef unsigned __int64 word64;
#else
typedef unsigned long long word64;
#endif

// 固定位数循环左移/右移，是 SHA 消息调度与轮函数的基本操作。
template <class T> inline T rotlFixed(T x, unsigned int y)
{
    assert(y < sizeof(T)*8);
    return T((x<<y) | (x>>(sizeof(T)*8-y)));
}

template <class T> inline T rotrFixed(T x, unsigned int y)
{
    assert(y < sizeof(T)*8);
    return T((x>>y) | (x<<(sizeof(T)*8-y)));
}

// ************** endian reversal ***************

#ifdef _MSC_VER
    #if _MSC_VER >= 1400
        #define CRYPTOPP_FAST_ROTATE(x) 1
    #elif _MSC_VER >= 1300
        #define CRYPTOPP_FAST_ROTATE(x) ((x) == 32 | (x) == 64)
    #else
        #define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
    #endif
#elif (defined(__MWERKS__) && TARGET_CPU_PPC) || \
    (defined(__GNUC__) && (defined(_ARCH_PWR2) || defined(_ARCH_PWR) || defined(_ARCH_PPC) || defined(_ARCH_PPC64) || defined(_ARCH_COM)))
    #define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
#elif defined(__GNUC__) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X86) // depend on GCC's peephole optimization to generate rotate instructions
    #define CRYPTOPP_FAST_ROTATE(x) 1
#else
    #define CRYPTOPP_FAST_ROTATE(x) 0
#endif

// 按整数宽度反转字节序；用于主机字序与 SHA 规定的大端字之间转换。
inline byte ByteReverse(byte value)
{
    return value;
}

inline word16 ByteReverse(word16 value)
{
#ifdef CRYPTOPP_BYTESWAP_AVAILABLE
    return bswap_16(value);
#elif defined(_MSC_VER) && _MSC_VER >= 1300
    return _byteswap_ushort(value);
#else
    return rotlFixed(value, 8U);
#endif
}

inline word32 ByteReverse(word32 value)
{
#if defined(__GNUC__)
    __asm__ ("bswap %0" : "=r" (value) : "0" (value));
    return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
    return bswap_32(value);
#elif defined(__MWERKS__) && TARGET_CPU_PPC
    return (word32)__lwbrx(&value,0);
#elif _MSC_VER >= 1400 || (_MSC_VER >= 1300 && !defined(_DLL))
    return _byteswap_ulong(value);
#elif CRYPTOPP_FAST_ROTATE(32)
    // 5 instructions with rotate instruction, 9 without
    return (rotrFixed(value, 8U) & 0xff00ff00) | (rotlFixed(value, 8U) & 0x00ff00ff);
#else
    // 6 instructions with rotate instruction, 8 without
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return rotlFixed(value, 16U);
#endif
}

#ifdef WORD64_AVAILABLE
inline word64 ByteReverse(word64 value)
{
#if defined(__GNUC__) && defined(__x86_64__)
    __asm__ ("bswap %0" : "=r" (value) : "0" (value));
    return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
    return bswap_64(value);
#elif defined(_MSC_VER) && _MSC_VER >= 1300
    return _byteswap_uint64(value);
#elif defined(CRYPTOPP_SLOW_WORD64)
    return (word64(ByteReverse(word32(value))) << 32) | ByteReverse(word32(value>>32));
#else
    value = ((value & W64LIT(0xFF00FF00FF00FF00)) >> 8) | ((value & W64LIT(0x00FF00FF00FF00FF)) << 8);
    value = ((value & W64LIT(0xFFFF0000FFFF0000)) >> 16) | ((value & W64LIT(0x0000FFFF0000FFFF)) << 16);
    return rotlFixed(value, 32U);
#endif
}
#endif


//
// SHA
//

// http://www.weidai.com/scan-mirror/md.html#SHA-1
// SHA-1 的初始向量与 512 位分组压缩函数。
class SHA1
{
public:
    typedef word32 HashWordType;
    static void InitState(word32 *state);
    static void Transform(word32 *digest, const word32 *data);
    static const char * StaticAlgorithmName() {return "SHA-1";}
};

typedef SHA1 SHA;   // for backwards compatibility

// implements the SHA-256 standard
// SHA-256 核心：8 个 32 位状态字，每次 Transform 消化 16 个 32 位输入字。
class SHA256
{
public:
    typedef word32 HashWordType;
    static void InitState(word32 *state);
    static void Transform(word32 *digest, const word32 *data);
    static const char * StaticAlgorithmName() {return "SHA-256";}
};

// implements the SHA-224 standard
// SHA-224 与 SHA-256 共用压缩函数，仅初始向量和最终截断长度不同。
class SHA224
{
public:
    typedef word32 HashWordType;
    static void InitState(word32 *state);
    static void Transform(word32 *digest, const word32 *data) {SHA256::Transform(digest, data);}
    static const char * StaticAlgorithmName() {return "SHA-224";}
};

#ifdef WORD64_AVAILABLE

// implements the SHA-512 standard
// SHA-512 核心使用 64 位状态字和 1024 位数据分组。
class SHA512
{
public:
    typedef word64 HashWordType;
    static void InitState(word64 *state);
    static void Transform(word64 *digest, const word64 *data);
    static const char * StaticAlgorithmName() {return "SHA-512";}
};

// implements the SHA-384 standard
// SHA-384 与 SHA-512 共用压缩函数，但采用不同初始向量并截断输出。
class SHA384
{
public:
    typedef word64 HashWordType;
    static void InitState(word64 *state);
    static void Transform(word64 *digest, const word64 *data) {SHA512::Transform(digest, data);}
    static const char * StaticAlgorithmName() {return "SHA-384";}
};

#endif

}

#endif
