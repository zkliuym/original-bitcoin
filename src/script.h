// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// script.h — Bitcoin v0.1.3 脚本语言的数据结构与接口
//=============================================================================
//
// 【本文件功能】
//   定义交易脚本使用的操作码、签名哈希类型和 CScript 字节码容器，并声明
//   脚本执行、标准脚本识别、签名生成与签名验证等入口。
//
// 【在整个系统中的作用】
//   1. 交易输出的 scriptPubKey 在这里表达“花费条件”，交易输入的 scriptSig
//      表达“解锁数据”；两段脚本共同决定某个 UTXO 能否被本次输入花费。
//   2. main.cpp 校验交易输入时经 VerifySignature 进入脚本解释器；钱包创建交易时
//      经 SignSignature/Solver 识别标准模板并生成对应的解锁脚本。
//   3. SignatureHash 按 SIGHASH 规则选择交易承诺范围，因此脚本字节布局和哈希
//      规则会直接影响交易有效性，属于所有节点必须一致执行的共识逻辑。
//
// 【阅读提示】
//   opcodetype → 字节码指令集；CScript → 构造/解析脚本；EvalScript → 执行；
//   Solver → 识别标准付款模板；SignSignature / VerifySignature → 钱包与验证入口。
//
//=============================================================================

class CTransaction;

// 签名哈希类型：低 5 位选择承诺哪些输出，最高位可把输入范围缩为当前输入。
enum
{
    SIGHASH_ALL = 1,             // 承诺全部输出（普通交易的默认模式）
    SIGHASH_NONE = 2,            // 不承诺任何输出，其他人可重新安排收款方
    SIGHASH_SINGLE = 3,          // 只承诺与当前输入下标相同的那个输出
    SIGHASH_ANYONECANPAY = 0x80, // 只承诺当前输入，可与上述三种模式按位组合
};



enum opcodetype
{
    // 压栈类：把紧随其后的字节串或小整数放入主栈，是 scriptSig 提供参数的基础。
    OP_0=0,
    OP_FALSE=OP_0,       // 空字节串，同时表示假
    OP_PUSHDATA1=76,     // 后 1 字节给出数据长度
    OP_PUSHDATA2,
    OP_PUSHDATA4,        // 分别用后 2/4 字节给出数据长度
    OP_1NEGATE,          // 压入 -1
    OP_RESERVED,
    OP_1,
    OP_TRUE=OP_1,        // OP_1～OP_16 以单操作码压入常用小整数
    OP_2,
    OP_3,
    OP_4,
    OP_5,
    OP_6,
    OP_7,
    OP_8,
    OP_9,
    OP_10,
    OP_11,
    OP_12,
    OP_13,
    OP_14,
    OP_15,
    OP_16,

    // 控制流：实现无循环的条件分支和显式失败；vfExec 记录嵌套分支状态。
    OP_NOP,              // 空操作
    OP_VER,              // 压入当前客户端协议版本（早期版本特有）
    OP_IF,               // 按栈顶真假选择分支
    OP_NOTIF,
    OP_VERIF,            // 早期按版本比较进行条件执行的操作码
    OP_VERNOTIF,
    OP_ELSE,
    OP_ENDIF,
    OP_VERIFY,           // 要求栈顶为真，否则使脚本失败
    OP_RETURN,           // 立即结束执行；由于不压入真值，通常导致失败

    // 栈操作：在主栈/备用栈间移动、复制、删除或重排元素，不解释元素内容。
    OP_TOALTSTACK,       // 主栈顶移入备用栈
    OP_FROMALTSTACK,
    OP_2DROP,
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,
    OP_IFDUP,
    OP_DEPTH,
    OP_DROP,
    OP_DUP,
    OP_NIP,
    OP_OVER,
    OP_PICK,
    OP_ROLL,
    OP_ROT,
    OP_SWAP,
    OP_TUCK,

    // 字节串操作：拼接、截取或取得长度；操作对象仍是栈中的原始字节向量。
    OP_CAT,              // 拼接两个字节串
    OP_SUBSTR,
    OP_LEFT,
    OP_RIGHT,
    OP_SIZE,             // 保留原值并把其字节长度压栈

    // 位逻辑与相等比较：逐字节运算，或比较两个栈元素的完整字节表示。
    OP_INVERT,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_EQUAL,            // 字节级相等，结果压栈
    OP_EQUALVERIFY,      // 相等后立即 VERIFY，P2PKH 模板使用它校验公钥哈希
    OP_RESERVED1,
    OP_RESERVED2,

    // 数值运算：把栈元素按 CBigNum 编码解释，执行一元/二元算术与比较。
    OP_1ADD,
    OP_1SUB,
    OP_2MUL,
    OP_2DIV,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,

    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_LSHIFT,
    OP_RSHIFT,

    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,

    OP_WITHIN,           // 判断 min <= x < max

    // 密码学操作：哈希数据、划定签名脚本片段、验证单签或多签。
    OP_RIPEMD160,
    OP_SHA1,
    OP_SHA256,
    OP_HASH160,          // SHA256 后 RIPEMD160，标准 P2PKH 公钥摘要使用
    OP_HASH256,          // 双 SHA256
    OP_CODESEPARATOR,    // 签名哈希只取最近分隔符之后的 scriptCode
    OP_CHECKSIG,         // 用公钥验证交易签名，结果真假压栈
    OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG,    // 按顺序用多个公钥匹配多个签名
    OP_CHECKMULTISIGVERIFY,


    // 操作码编码边界：普通操作码占 1 字节，实验性扩展操作码可占 2 字节。
    OP_SINGLEBYTE_END = 0xF0,
    OP_DOUBLEBYTE_BEGIN = 0xF000,

    // Solver 专用模板占位符，不是由 EvalScript 执行的真实交易操作码。
    OP_PUBKEY,           // 匹配一段完整公钥数据
    OP_PUBKEYHASH,       // 匹配 20 字节公钥哈希



    OP_INVALIDOPCODE = 0xFFFF,
};








// 把操作码转换为便于日志和脚本反汇编显示的名称。
inline const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";



    // multi-byte opcodes
    case OP_SINGLEBYTE_END         : return "OP_SINGLEBYTE_END";
    case OP_DOUBLEBYTE_BEGIN       : return "OP_DOUBLEBYTE_BEGIN";
    case OP_PUBKEY                 : return "OP_PUBKEY";
    case OP_PUBKEYHASH             : return "OP_PUBKEYHASH";



    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";
    default:
        return "UNKNOWN_OPCODE";
    }
};




// 调试显示：短字节串按脚本数字解释，较长数据以十六进制显示。
inline string ValueString(const vector<unsigned char>& vch)
{
    if (vch.size() <= 4)
        return strprintf("%d", CBigNum(vch).getint());
    else
        return HexNumStr(vch.begin(), vch.end());
        //return string("(") + HexStr(vch.begin(), vch.end()) + string(")");
}

// 把整个执行栈格式化为一行，供调试跟踪使用。
inline string StackString(const vector<vector<unsigned char> >& vStack)
{
    string str;
    foreach(const vector<unsigned char>& vch, vStack)
    {
        if (!str.empty())
            str += " ";
        str += ValueString(vch);
    }
    return str;
}









// CScript 是脚本的原始字节码容器。
// 它继承 vector<unsigned char>，既能直接序列化进交易，也提供 << 构造指令、
// GetOp 顺序解码、FindAndDelete 准备签名哈希以及 ToString 反汇编等能力。
class CScript : public vector<unsigned char>
{
protected:
    // 按脚本数字规则压入有符号整数；-1 和 1～16 使用专用短操作码。
    CScript& push_int64(int64 n)
    {
        if (n == -1 || (n >= 1 && n <= 16))
        {
            push_back(n + (OP_1 - 1));
        }
        else
        {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return (*this);
    }

    // 无符号整数版本；不能用短操作码时转成 CBigNum 字节表示再压栈。
    CScript& push_uint64(uint64 n)
    {
        if (n == -1 || (n >= 1 && n <= 16))
        {
            push_back(n + (OP_1 - 1));
        }
        else
        {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return (*this);
    }

public:
    CScript() { }
    CScript(const CScript& b) : vector<unsigned char>(b.begin(), b.end()) { }
    CScript(const_iterator pbegin, const_iterator pend) : vector<unsigned char>(pbegin, pend) { }
#ifndef _MSC_VER
    CScript(const unsigned char* pbegin, const unsigned char* pend) : vector<unsigned char>(pbegin, pend) { }
#endif

    CScript& operator+=(const CScript& b)
    {
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript& a, const CScript& b)
    {
        CScript ret = a;
        ret += b;
        return (ret);
    }


    explicit CScript(char b)           { operator<<(b); }
    explicit CScript(short b)          { operator<<(b); }
    explicit CScript(int b)            { operator<<(b); }
    explicit CScript(long b)           { operator<<(b); }
    explicit CScript(int64 b)          { operator<<(b); }
    explicit CScript(unsigned char b)  { operator<<(b); }
    explicit CScript(unsigned int b)   { operator<<(b); }
    explicit CScript(unsigned short b) { operator<<(b); }
    explicit CScript(unsigned long b)  { operator<<(b); }
    explicit CScript(uint64 b)         { operator<<(b); }

    explicit CScript(opcodetype b)     { operator<<(b); }
    explicit CScript(const uint256& b) { operator<<(b); }
    explicit CScript(const CBigNum& b) { operator<<(b); }
    explicit CScript(const vector<unsigned char>& b) { operator<<(b); }


    CScript& operator<<(char b)           { return (push_int64(b)); }
    CScript& operator<<(short b)          { return (push_int64(b)); }
    CScript& operator<<(int b)            { return (push_int64(b)); }
    CScript& operator<<(long b)           { return (push_int64(b)); }
    CScript& operator<<(int64 b)          { return (push_int64(b)); }
    CScript& operator<<(unsigned char b)  { return (push_uint64(b)); }
    CScript& operator<<(unsigned int b)   { return (push_uint64(b)); }
    CScript& operator<<(unsigned short b) { return (push_uint64(b)); }
    CScript& operator<<(unsigned long b)  { return (push_uint64(b)); }
    CScript& operator<<(uint64 b)         { return (push_uint64(b)); }

    // 追加一条操作码；早期实现同时保留了双字节扩展操作码编码。
    CScript& operator<<(opcodetype opcode)
    {
        if (opcode <= OP_SINGLEBYTE_END)
        {
            insert(end(), (unsigned char)opcode);
        }
        else
        {
            assert(opcode >= OP_DOUBLEBYTE_BEGIN);
            insert(end(), (unsigned char)(opcode >> 8));
            insert(end(), (unsigned char)(opcode & 0xFF));
        }
        return (*this);
    }

    // 固定宽度哈希也作为“长度前缀 + 原始字节”的压栈数据写入脚本。
    CScript& operator<<(const uint160& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return (*this);
    }

    CScript& operator<<(const uint256& b)
    {
        insert(end(), sizeof(b));
        insert(end(), (unsigned char*)&b, (unsigned char*)&b + sizeof(b));
        return (*this);
    }

    CScript& operator<<(const CBigNum& b)
    {
        *this << b.getvch();
        return (*this);
    }

    // 追加一段压栈数据，并按长度自动选择直接长度、PUSHDATA1 或 PUSHDATA2。
    CScript& operator<<(const vector<unsigned char>& b)
    {
        if (b.size() < OP_PUSHDATA1)
        {
            insert(end(), (unsigned char)b.size());
        }
        else if (b.size() <= 0xff)
        {
            insert(end(), OP_PUSHDATA1);
            insert(end(), (unsigned char)b.size());
        }
        else
        {
            insert(end(), OP_PUSHDATA2);
            unsigned short nSize = b.size();
            insert(end(), (unsigned char*)&nSize, (unsigned char*)&nSize + sizeof(nSize));
        }
        insert(end(), b.begin(), b.end());
        return (*this);
    }

    CScript& operator<<(const CScript& b)
    {
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this member fn
        assert(("warning: pushing a CScript onto a CScript with << is probably not intended, use + to concatenate", false));
        return (*this);
    }


    // 可写迭代器包装：复用 const 解析实现，并把更新后的位置映射回来。
    bool GetOp(iterator& pc, opcodetype& opcodeRet, vector<unsigned char>& vchRet)
    {
         // This is why people hate C++
         const_iterator pc2 = pc;
         bool fRet = GetOp(pc2, opcodeRet, vchRet);
         pc = begin() + (pc2 - begin());
         return fRet;
    }

    // 从 pc 解码一条指令；若为压栈指令，同时返回其数据并推进 pc。
    // 遇到截断的操作码、长度字段或载荷时返回 false，防止越界读取。
    bool GetOp(const_iterator& pc, opcodetype& opcodeRet, vector<unsigned char>& vchRet) const
    {
        opcodeRet = OP_INVALIDOPCODE;
        vchRet.clear();
        if (pc >= end())
            return false;

        // Read instruction
        unsigned int opcode = *pc++;
        if (opcode >= OP_SINGLEBYTE_END)
        {
            if (pc + 1 > end())
                return false;
            opcode <<= 8;
            opcode |= *pc++;
        }

        // Immediate operand
        if (opcode <= OP_PUSHDATA4)
        {
            unsigned int nSize = opcode;
            if (opcode == OP_PUSHDATA1)
            {
                if (pc + 1 > end())
                    return false;
                nSize = *pc++;
            }
            else if (opcode == OP_PUSHDATA2)
            {
                if (pc + 2 > end())
                    return false;
                nSize = 0;
                memcpy(&nSize, &pc[0], 2);
                pc += 2;
            }
            else if (opcode == OP_PUSHDATA4)
            {
                if (pc + 4 > end())
                    return false;
                memcpy(&nSize, &pc[0], 4);
                pc += 4;
            }
            if (pc + nSize > end())
                return false;
            vchRet.assign(pc, pc + nSize);
            pc += nSize;
        }

        opcodeRet = (opcodetype)opcode;
        return true;
    }


    // 仅在指令边界查找并删除字节序列；签名哈希前用它移除签名自身和 CODESEPARATOR。
    void FindAndDelete(const CScript& b)
    {
        iterator pc = begin();
        opcodetype opcode;
        vector<unsigned char> vchPushValue;
        int count = 0;
        do
        {
            while (end() - pc >= b.size() && memcmp(&pc[0], &b[0], b.size()) == 0)
            {
                erase(pc, pc + b.size());
                count++;
            }
        }
        while (GetOp(pc, opcode, vchPushValue));
        //printf("FindAndDeleted deleted %d items\n", count); /// debug
    }


    void PrintHex() const
    {
        printf("CScript(%s)\n", HexStr(begin(), end()).c_str());
    }

    // 顺序反汇编脚本：压栈项显示值，其他指令显示操作码名称。
    string ToString() const
    {
        string str;
        opcodetype opcode;
        vector<unsigned char> vch;
        const_iterator it = begin();
        while (GetOp(it, opcode, vch))
        {
            if (!str.empty())
                str += " ";
            if (opcode <= OP_PUSHDATA4)
                str += ValueString(vch);
            else
                str += GetOpName(opcode);
        }
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};








// 执行脚本并以最终主栈栈顶真假作为结果；可选返回执行后的栈。
bool EvalScript(const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType=0,
                vector<vector<unsigned char> >* pvStackRet=NULL);
// 构造当前输入要签名/验证的交易副本，并按 SIGHASH 模式计算双 SHA256。
uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);
// 以下辅助接口由 Solver 识别本版本支持的标准 P2PK/P2PKH 输出。
bool IsMine(const CScript& scriptPubKey);
bool ExtractPubKey(const CScript& scriptPubKey, bool fMineOnly, vector<unsigned char>& vchPubKeyRet);
bool ExtractHash160(const CScript& scriptPubKey, uint160& hash160Ret);
// 钱包签名入口：为 txTo 的第 nIn 个输入生成 scriptSig。
bool SignSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL, CScript scriptPrereq=CScript());
// 交易验证入口：确认 prevout 指向 txFrom 后，执行 scriptSig + scriptPubKey。
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType=0);
