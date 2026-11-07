// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// headers.h — Bitcoin v0.1.3 预编译头（PCH）总入口
//=============================================================================
//
// 【本文件功能】
//   集中包含 wxWidgets、OpenSSL、Win32、STL/Boost 以及项目内部主要头文件，
//   让 Visual C++ 通过预编译头减少整套客户端的重复编译开销。
//
// 【在整个系统中的作用】
//   多数 .cpp 只需包含本文件即可获得平台 API 和 Bitcoin 各模块声明；其包含顺序
//   也体现旧版代码的高耦合构建方式。它不是一个业务模块，不定义协议或共识逻辑。
//
// 【阅读提示】
//   前半段是第三方/系统依赖与 Windows 兼容配置，#pragma hdrstop 之后是项目头。
//   排查某类型“为何无需显式 include”时，可从这里追踪其间接包含来源。
//
//=============================================================================

#ifdef _MSC_VER
// 兼容早期 MSVC：关闭模板调试名过长、布尔运算及递归内联相关警告。
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4717)
#endif
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0400
#define WIN32_LEAN_AND_MEAN 1
// GUI、密码库、Windows 网络/系统 API 与 C/C++ 标准库依赖。
#include <wx/wx.h>
#include <wx/clipbrd.h>
#include <wx/snglinst.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <math.h>
#include <limits.h>
#include <float.h>
#include <assert.h>
#include <process.h>
#include <malloc.h>
#include <memory>
#define BOUNDSCHECK 1
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <deque>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/tuple/tuple_io.hpp>
#include <boost/array.hpp>
#pragma hdrstop
using namespace std;
using namespace boost;



// 项目内部模块的总括包含；serialize/基础数值先于上层脚本、数据库、网络和界面。
#include "serialize.h"
#include "uint256.h"
#include "util.h"
#include "key.h"
#include "bignum.h"
#include "base58.h"
#include "script.h"
#include "db.h"
#include "net.h"
#include "irc.h"
#include "main.h"
#include "market.h"
#include "uibase.h"
#include "ui.h"
