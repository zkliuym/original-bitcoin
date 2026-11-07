// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// irc.h — Bitcoin v0.1.3 的 IRC 节点发现接口
//=============================================================================
//
// 【本文件功能】
//   声明按行读取 socket 的工具函数，以及通过 IRC 频道发现节点的线程入口。
//
// 【在整个系统中的作用】
//   节点启动时尚无现代 DNS seed。ThreadIRCSeed 把自身 IP/端口编码为昵称加入
//   #bitcoin，并从频道成员昵称恢复其他 CAddress，写入网络地址簿供出站连接。
//
// 【阅读提示】
//   RecvLine 是通用 CRLF 读取器；IRC 的 PING/PONG、昵称编解码和重连流程
//   均在 irc.cpp。该机制只负责“发现地址”，不承载交易或区块数据。
//
//=============================================================================

// 从 socket 读取一行，以 '\r' 结束并忽略 '\n'。
extern bool RecvLine(SOCKET hSocket, string& strLine);
// IRC 节点发现后台线程。
extern void ThreadIRCSeed(void* parg);
// 请求重新启动 IRC seed 的历史状态标志（由其他模块声明/使用）。
extern bool fRestartIRCSeed;
