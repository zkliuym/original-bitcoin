// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// script.cpp — Bitcoin v0.1.3 脚本解释、签名哈希与标准脚本求解
//=============================================================================
//
// 【本文件功能】
//   实现基于栈的脚本解释器 EvalScript，按 SIGHASH 规则生成待签名摘要，
//   用椭圆曲线公钥校验签名，并识别、签署本版本支持的标准 P2PK/P2PKH 脚本。
//
// 【在整个系统中的作用】
//   1. 共识验证：VerifySignature 把输入的 scriptSig 与被花费输出的 scriptPubKey
//      连接执行，最终栈顶必须为真，交易输入才被节点接受。
//   2. 钱包签名：SignSignature 找到前序输出，SignatureHash 生成承诺摘要，
//      Solver 从钱包密钥表选择私钥并构造 scriptSig。
//   3. 脚本策略：Solver 只认识少量“标准模板”，用于钱包和 IsMine；EvalScript
//      则执行完整操作码集合。模板识别失败不等同于脚本在共识上必然无效。
//
// 【阅读主线】
//   VerifySignature → EvalScript → OP_CHECKSIG → CheckSig → SignatureHash；
//   创建交易时则是 SignSignature → Solver → CKey::Sign。
//
//=============================================================================

#include "headers.h"

// 校验单个签名：解析公钥和签名尾部哈希类型，再验证 SignatureHash。
bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);



typedef vector<unsigned char> valtype;
// 脚本栈元素统一为原始字节串；空串是假，数值 1 的编码是真。
static const valtype vchFalse(0);
static const valtype vchZero(0);
static const valtype vchTrue(1, 1);
static const CBigNum bnZero(0);
static const CBigNum bnOne(1);
static const CBigNum bnFalse(0);
static const CBigNum bnTrue(1);


// 按脚本数字编码把栈元素解释为布尔值。
bool CastToBool(const valtype& vch)
{
    return (CBigNum(vch) != bnZero);
}

// 位运算前用零扩展较短操作数，使两个字节串等长。
void MakeSameSize(valtype& vch1, valtype& vch2)
{
    // Lengthen the shorter one
    if (vch1.size() < vch2.size())
        vch1.resize(vch2.size(), 0);
    if (vch2.size() < vch1.size())
        vch2.resize(vch1.size(), 0);
}



//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
// EvalScript 是无循环的栈式解释器：
//   stack 保存主数据，altstack 是临时备用栈，vfExec 跟踪嵌套条件分支；
//   每轮由 CScript::GetOp 解码一条指令，只执行当前活动分支中的普通操作码；
//   执行结束后，主栈非空且栈顶为真才算成功。
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))

bool EvalScript(const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType,
                vector<vector<unsigned char> >* pvStackRet)
{
    CAutoBN_CTX pctx;
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    vector<bool> vfExec;
    vector<valtype> stack;
    vector<valtype> altstack;
    if (pvStackRet)
        pvStackRet->clear();


    while (pc < pend)
    {
        bool fExec = !count(vfExec.begin(), vfExec.end(), false);

        //
        // 取指：解析操作码及可选的内嵌压栈数据；格式截断立即失败。
        //
        opcodetype opcode;
        valtype vchPushValue;
        if (!script.GetOp(pc, opcode, vchPushValue))
            return false;

        // 数据压栈指令无需进入 switch；非活动分支只处理 IF～ENDIF 以维持嵌套结构。
        if (fExec && opcode <= OP_PUSHDATA4)
            stack.push_back(vchPushValue);
        else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
        switch (opcode)
        {
            //
            // 常量压栈：用专用操作码把 -1、1～16 编码成 CBigNum 栈元素。
            //
            case OP_1NEGATE:
            case OP_1:
            case OP_2:
            case OP_3:
            case OP_4:
            case OP_5:
            case OP_6:
            case OP_7:
            case OP_8:
            case OP_9:
            case OP_10:
            case OP_11:
            case OP_12:
            case OP_13:
            case OP_14:
            case OP_15:
            case OP_16:
            {
                // ( -- value)
                CBigNum bn((int)opcode - (int)(OP_1 - 1));
                stack.push_back(bn.getvch());
            }
            break;


            //
            // 控制流：vfExec 保存每层条件真假；脚本没有跳转和循环。
            //
            case OP_NOP:
            break;

            case OP_VER:
            {
                CBigNum bn(VERSION);
                stack.push_back(bn.getvch());
            }
            break;

            case OP_IF:
            case OP_NOTIF:
            case OP_VERIF:
            case OP_VERNOTIF:
            {
                // <expression> if [statements] [else [statements]] endif
                bool fValue = false;
                if (fExec)
                {
                    if (stack.size() < 1)
                        return false;
                    valtype& vch = stacktop(-1);
                    if (opcode == OP_VERIF || opcode == OP_VERNOTIF)
                        fValue = (CBigNum(VERSION) >= CBigNum(vch));
                    else
                        fValue = CastToBool(vch);
                    if (opcode == OP_NOTIF || opcode == OP_VERNOTIF)
                        fValue = !fValue;
                    stack.pop_back();
                }
                vfExec.push_back(fValue);
            }
            break;

            case OP_ELSE:
            {
                if (vfExec.empty())
                    return false;
                vfExec.back() = !vfExec.back();
            }
            break;

            case OP_ENDIF:
            {
                if (vfExec.empty())
                    return false;
                vfExec.pop_back();
            }
            break;

            case OP_VERIFY:
            {
                // (true -- ) or
                // (false -- false) and return
                if (stack.size() < 1)
                    return false;
                bool fValue = CastToBool(stacktop(-1));
                if (fValue)
                    stack.pop_back();
                else
                    pc = pend;
            }
            break;

            case OP_RETURN:
            {
                pc = pend;
            }
            break;


            //
            // 栈操作：移动、复制、删除和重排主栈/备用栈元素。
            //
            case OP_TOALTSTACK:
            {
                if (stack.size() < 1)
                    return false;
                altstack.push_back(stacktop(-1));
                stack.pop_back();
            }
            break;

            case OP_FROMALTSTACK:
            {
                if (altstack.size() < 1)
                    return false;
                stack.push_back(altstacktop(-1));
                altstack.pop_back();
            }
            break;

            case OP_2DROP:
            {
                // (x1 x2 -- )
                // 早期实现此处没有显式深度检查；按历史代码原样说明，不改变逻辑。
                stack.pop_back();
                stack.pop_back();
            }
            break;

            case OP_2DUP:
            {
                // (x1 x2 -- x1 x2 x1 x2)
                if (stack.size() < 2)
                    return false;
                valtype vch1 = stacktop(-2);
                valtype vch2 = stacktop(-1);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_3DUP:
            {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                if (stack.size() < 3)
                    return false;
                valtype vch1 = stacktop(-3);
                valtype vch2 = stacktop(-2);
                valtype vch3 = stacktop(-1);
                stack.push_back(vch1);
                stack.push_back(vch2);
                stack.push_back(vch3);
            }
            break;

            case OP_2OVER:
            {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                if (stack.size() < 4)
                    return false;
                valtype vch1 = stacktop(-4);
                valtype vch2 = stacktop(-3);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_2ROT:
            {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                if (stack.size() < 6)
                    return false;
                valtype vch1 = stacktop(-6);
                valtype vch2 = stacktop(-5);
                stack.erase(stack.end()-6, stack.end()-4);
                stack.push_back(vch1);
                stack.push_back(vch2);
            }
            break;

            case OP_2SWAP:
            {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                if (stack.size() < 4)
                    return false;
                swap(stacktop(-4), stacktop(-2));
                swap(stacktop(-3), stacktop(-1));
            }
            break;

            case OP_IFDUP:
            {
                // (x - 0 | x x)
                if (stack.size() < 1)
                    return false;
                valtype vch = stacktop(-1);
                if (CastToBool(vch))
                    stack.push_back(vch);
            }
            break;

            case OP_DEPTH:
            {
                // -- stacksize
                CBigNum bn(stack.size());
                stack.push_back(bn.getvch());
            }
            break;

            case OP_DROP:
            {
                // (x -- )
                if (stack.size() < 1)
                    return false;
                stack.pop_back();
            }
            break;

            case OP_DUP:
            {
                // (x -- x x)
                if (stack.size() < 1)
                    return false;
                valtype vch = stacktop(-1);
                stack.push_back(vch);
            }
            break;

            case OP_NIP:
            {
                // (x1 x2 -- x2)
                if (stack.size() < 2)
                    return false;
                stack.erase(stack.end() - 2);
            }
            break;

            case OP_OVER:
            {
                // (x1 x2 -- x1 x2 x1)
                if (stack.size() < 2)
                    return false;
                valtype vch = stacktop(-2);
                stack.push_back(vch);
            }
            break;

            case OP_PICK:
            case OP_ROLL:
            {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                if (stack.size() < 2)
                    return false;
                int n = CBigNum(stacktop(-1)).getint();
                stack.pop_back();
                if (n < 0 || n >= stack.size())
                    return false;
                valtype vch = stacktop(-n-1);
                if (opcode == OP_ROLL)
                    stack.erase(stack.end()-n-1);
                stack.push_back(vch);
            }
            break;

            case OP_ROT:
            {
                // (x1 x2 x3 -- x2 x3 x1)
                //  x2 x1 x3  after first swap
                //  x2 x3 x1  after second swap
                if (stack.size() < 3)
                    return false;
                swap(stacktop(-3), stacktop(-2));
                swap(stacktop(-2), stacktop(-1));
            }
            break;

            case OP_SWAP:
            {
                // (x1 x2 -- x2 x1)
                if (stack.size() < 2)
                    return false;
                swap(stacktop(-2), stacktop(-1));
            }
            break;

            case OP_TUCK:
            {
                // (x1 x2 -- x2 x1 x2)
                if (stack.size() < 2)
                    return false;
                valtype vch = stacktop(-1);
                stack.insert(stack.end()-2, vch);
            }
            break;


            //
            // 字节串操作：拼接、切片和长度查询，不进行数值解释。
            //
            case OP_CAT:
            {
                // (x1 x2 -- out)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                stack.pop_back();
            }
            break;

            case OP_SUBSTR:
            {
                // (in begin size -- out)
                if (stack.size() < 3)
                    return false;
                valtype& vch = stacktop(-3);
                int nBegin = CBigNum(stacktop(-2)).getint();
                int nEnd = nBegin + CBigNum(stacktop(-1)).getint();
                if (nBegin < 0 || nEnd < nBegin)
                    return false;
                if (nBegin > vch.size())
                    nBegin = vch.size();
                if (nEnd > vch.size())
                    nEnd = vch.size();
                vch.erase(vch.begin() + nEnd, vch.end());
                vch.erase(vch.begin(), vch.begin() + nBegin);
                stack.pop_back();
                stack.pop_back();
            }
            break;

            case OP_LEFT:
            case OP_RIGHT:
            {
                // (in size -- out)
                if (stack.size() < 2)
                    return false;
                valtype& vch = stacktop(-2);
                int nSize = CBigNum(stacktop(-1)).getint();
                if (nSize < 0)
                    return false;
                if (nSize > vch.size())
                    nSize = vch.size();
                if (opcode == OP_LEFT)
                    vch.erase(vch.begin() + nSize, vch.end());
                else
                    vch.erase(vch.begin(), vch.end() - nSize);
                stack.pop_back();
            }
            break;

            case OP_SIZE:
            {
                // (in -- in size)
                if (stack.size() < 1)
                    return false;
                CBigNum bn(stacktop(-1).size());
                stack.push_back(bn.getvch());
            }
            break;


            //
            // 位逻辑与相等比较：位运算先零扩展到相同长度，相等则比较完整字节串。
            //
            case OP_INVERT:
            {
                // (in - out)
                if (stack.size() < 1)
                    return false;
                valtype& vch = stacktop(-1);
                for (int i = 0; i < vch.size(); i++)
                    vch[i] = ~vch[i];
            }
            break;

            case OP_AND:
            case OP_OR:
            case OP_XOR:
            {
                // (x1 x2 - out)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                MakeSameSize(vch1, vch2);
                if (opcode == OP_AND)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] &= vch2[i];
                }
                else if (opcode == OP_OR)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] |= vch2[i];
                }
                else if (opcode == OP_XOR)
                {
                    for (int i = 0; i < vch1.size(); i++)
                        vch1[i] ^= vch2[i];
                }
                stack.pop_back();
            }
            break;

            case OP_EQUAL:
            case OP_EQUALVERIFY:
            //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
            {
                // (x1 x2 - bool)
                if (stack.size() < 2)
                    return false;
                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);
                bool fEqual = (vch1 == vch2);
                // OP_NOTEQUAL is disabled because it would be too easy to say
                // something like n != 1 and have some wiseguy pass in 1 with extra
                // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                //if (opcode == OP_NOTEQUAL)
                //    fEqual = !fEqual;
                stack.pop_back();
                stack.pop_back();
                stack.push_back(fEqual ? vchTrue : vchFalse);
                if (opcode == OP_EQUALVERIFY)
                {
                    if (fEqual)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;


            //
            // 数值操作：把栈元素解码为 CBigNum，运算后再编码回字节串。
            //
            case OP_1ADD:
            case OP_1SUB:
            case OP_2MUL:
            case OP_2DIV:
            case OP_NEGATE:
            case OP_ABS:
            case OP_NOT:
            case OP_0NOTEQUAL:
            {
                // (in -- out)
                if (stack.size() < 1)
                    return false;
                CBigNum bn(stacktop(-1));
                switch (opcode)
                {
                case OP_1ADD:       bn += bnOne; break;
                case OP_1SUB:       bn -= bnOne; break;
                case OP_2MUL:       bn <<= 1; break;
                case OP_2DIV:       bn >>= 1; break;
                case OP_NEGATE:     bn = -bn; break;
                case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                case OP_NOT:        bn = (bn == bnZero); break;
                case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                }
                stack.pop_back();
                stack.push_back(bn.getvch());
            }
            break;

            case OP_ADD:
            case OP_SUB:
            case OP_MUL:
            case OP_DIV:
            case OP_MOD:
            case OP_LSHIFT:
            case OP_RSHIFT:
            case OP_BOOLAND:
            case OP_BOOLOR:
            case OP_NUMEQUAL:
            case OP_NUMEQUALVERIFY:
            case OP_NUMNOTEQUAL:
            case OP_LESSTHAN:
            case OP_GREATERTHAN:
            case OP_LESSTHANOREQUAL:
            case OP_GREATERTHANOREQUAL:
            case OP_MIN:
            case OP_MAX:
            {
                // (x1 x2 -- out)
                if (stack.size() < 2)
                    return false;
                CBigNum bn1(stacktop(-2));
                CBigNum bn2(stacktop(-1));
                CBigNum bn;
                switch (opcode)
                {
                case OP_ADD:
                    bn = bn1 + bn2;
                    break;

                case OP_SUB:
                    bn = bn1 - bn2;
                    break;

                case OP_MUL:
                    if (!BN_mul(&bn, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_DIV:
                    if (!BN_div(&bn, NULL, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_MOD:
                    if (!BN_mod(&bn, &bn1, &bn2, pctx))
                        return false;
                    break;

                case OP_LSHIFT:
                    if (bn2 < bnZero)
                        return false;
                    bn = bn1 << bn2.getulong();
                    break;

                case OP_RSHIFT:
                    if (bn2 < bnZero)
                        return false;
                    bn = bn1 >> bn2.getulong();
                    break;

                case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                }
                stack.pop_back();
                stack.pop_back();
                stack.push_back(bn.getvch());

                if (opcode == OP_NUMEQUALVERIFY)
                {
                    if (CastToBool(stacktop(-1)))
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            case OP_WITHIN:
            {
                // (x min max -- out)
                if (stack.size() < 3)
                    return false;
                CBigNum bn1(stacktop(-3));
                CBigNum bn2(stacktop(-2));
                CBigNum bn3(stacktop(-1));
                bool fValue = (bn2 <= bn1 && bn1 < bn3);
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.push_back(fValue ? vchTrue : vchFalse);
            }
            break;


            //
            // 密码学操作：哈希栈元素，以及按当前交易上下文验证签名。
            //
            case OP_RIPEMD160:
            case OP_SHA1:
            case OP_SHA256:
            case OP_HASH160:
            case OP_HASH256:
            {
                // (in -- hash)
                if (stack.size() < 1)
                    return false;
                valtype& vch = stacktop(-1);
                valtype vchHash(opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160 ? 20 : 32);
                if (opcode == OP_RIPEMD160)
                    RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_SHA1)
                    SHA1(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_SHA256)
                    SHA256(&vch[0], vch.size(), &vchHash[0]);
                else if (opcode == OP_HASH160)
                {
                    uint160 hash160 = Hash160(vch);
                    memcpy(&vchHash[0], &hash160, sizeof(hash160));
                }
                else if (opcode == OP_HASH256)
                {
                    uint256 hash = Hash(vch.begin(), vch.end());
                    memcpy(&vchHash[0], &hash, sizeof(hash));
                }
                stack.pop_back();
                stack.push_back(vchHash);
            }
            break;

            case OP_CODESEPARATOR:
            {
                // Hash starts after the code separator
                // 后续 CHECKSIG 的 scriptCode 从这里开始，分隔符之前的脚本不进签名哈希。
                pbegincodehash = pc;
            }
            break;

            case OP_CHECKSIG:
            case OP_CHECKSIGVERIFY:
            {
                // (sig pubkey -- bool)
                if (stack.size() < 2)
                    return false;

                valtype& vchSig    = stacktop(-2);
                valtype& vchPubKey = stacktop(-1);

                ////// debug print
                //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
                //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");

                // 取最近 CODESEPARATOR 之后的脚本作为签名承诺脚本。
                CScript scriptCode(pbegincodehash, pend);

                // Drop the signature, since there's no way for a signature to sign itself
                // 删除签名自身，避免“签名内容包含自身”形成递归依赖。
                scriptCode.FindAndDelete(CScript(vchSig));

                bool fSuccess = CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType);

                stack.pop_back();
                stack.pop_back();
                stack.push_back(fSuccess ? vchTrue : vchFalse);
                if (opcode == OP_CHECKSIGVERIFY)
                {
                    if (fSuccess)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY:
            {
                // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
                // 签名和公钥均保持原顺序向前匹配；某公钥失败后可继续尝试下一个，
                // 但剩余签名数一旦多于剩余公钥数，就不可能再全部匹配。

                int i = 1;
                if (stack.size() < i)
                    return false;

                int nKeysCount = CBigNum(stacktop(-i)).getint();
                if (nKeysCount < 0)
                    return false;
                int ikey = ++i;
                i += nKeysCount;
                if (stack.size() < i)
                    return false;

                int nSigsCount = CBigNum(stacktop(-i)).getint();
                if (nSigsCount < 0 || nSigsCount > nKeysCount)
                    return false;
                int isig = ++i;
                i += nSigsCount;
                if (stack.size() < i)
                    return false;

                // Subset of script starting at the most recent codeseparator
                CScript scriptCode(pbegincodehash, pend);

                // Drop the signatures, since there's no way for a signature to sign itself
                for (int i = 0; i < nSigsCount; i++)
                {
                    valtype& vchSig = stacktop(-isig-i);
                    scriptCode.FindAndDelete(CScript(vchSig));
                }

                bool fSuccess = true;
                while (fSuccess && nSigsCount > 0)
                {
                    valtype& vchSig    = stacktop(-isig);
                    valtype& vchPubKey = stacktop(-ikey);

                    // Check signature
                    if (CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType))
                    {
                        isig++;
                        nSigsCount--;
                    }
                    ikey++;
                    nKeysCount--;

                    // If there are more signatures left than keys left,
                    // then too many signatures have failed
                    if (nSigsCount > nKeysCount)
                        fSuccess = false;
                }

                while (i-- > 0)
                    stack.pop_back();
                stack.push_back(fSuccess ? vchTrue : vchFalse);

                if (opcode == OP_CHECKMULTISIGVERIFY)
                {
                    if (fSuccess)
                        stack.pop_back();
                    else
                        pc = pend;
                }
            }
            break;

            default:
                return false;
        }
    }


    // 调试调用方可取得最终主栈；正常验证只关心最终栈顶的布尔值。
    if (pvStackRet)
        *pvStackRet = stack;
    return (stack.empty() ? false : CastToBool(stack.back()));
}

#undef top









// 生成签名摘要：复制交易并按 nHashType 清空不需要承诺的字段，
// 最后序列化“修改后的交易 + 4 字节哈希类型”并做双 SHA256。
uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }
    CTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    scriptCode.FindAndDelete(CScript(OP_CODESEPARATOR));

    // 所有输入先清空 scriptSig，仅当前输入放入正在验证的 scriptCode。
    for (int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // 低 5 位决定输出承诺范围：ALL 保留全部，NONE 清空，SINGLE 只保留同下标输出。
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // 不绑定收款输出。
        txTmp.vout.clear();

        // 其他输入的 sequence 归零，使其不在此模式下被签名约束。
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // 只绑定与当前输入同下标的输出；之前的输出置空作为占位。
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            printf("ERROR: SignatureHash() : nOut=%d out of range\n", nOut);
            return 1;
        }
        txTmp.vout.resize(nOut+1);
        for (int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        for (int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // ANYONECANPAY 只保留当前输入，允许其他参与者后续追加自己的输入。
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // SER_GETHASH 使用共识序列化格式；哈希类型作为交易后的额外字段参与摘要。
    CDataStream ss(SER_GETHASH);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    return Hash(ss.begin(), ss.end());
}


// OP_CHECKSIG/OP_CHECKMULTISIG 的共同底层：签名最后一字节不是 DER 签名内容，
// 而是 SIGHASH 模式；移除该字节后再调用 CKey::Verify。
bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode,
              const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    CKey key;
    if (!key.SetPubKey(vchPubKey))
        return false;

    // Hash type is one byte tacked on to the end of the signature
    if (vchSig.empty())
        return false;
    if (nHashType == 0)
        nHashType = vchSig.back();
    else if (nHashType != vchSig.back())
        return false;
    vchSig.pop_back();

    if (key.Verify(SignatureHash(scriptCode, txTo, nIn, nHashType), vchSig))
        return true;

    return false;
}











// 将 scriptPubKey 与本版本认可的标准模板逐指令匹配，并提取模板参数。
// 当前模板只有：<pubkey> CHECKSIG（P2PK）和
// DUP HASH160 <pubkeyhash> EQUALVERIFY CHECKSIG（后来称为 P2PKH）。
bool Solver(const CScript& scriptPubKey, vector<pair<opcodetype, valtype> >& vSolutionRet)
{
    // 模板中的 OP_PUBKEY/OP_PUBKEYHASH 是匹配占位符，不会交给 EvalScript 执行。
    static vector<CScript> vTemplates;
    if (vTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        vTemplates.push_back(CScript() << OP_PUBKEY << OP_CHECKSIG);

        // Short account number tx, sender provides hash of pubkey, receiver provides signature and pubkey
        vTemplates.push_back(CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG);
    }

    // 逐条扫描候选模板；占位符校验长度并保存实际值，其余操作码必须完全相同。
    const CScript& script1 = scriptPubKey;
    foreach(const CScript& script2, vTemplates)
    {
        vSolutionRet.clear();
        opcodetype opcode1, opcode2;
        vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        loop
        {
            bool f1 = script1.GetOp(pc1, opcode1, vch1);
            bool f2 = script2.GetOp(pc2, opcode2, vch2);
            if (!f1 && !f2)
            {
                // Success
                reverse(vSolutionRet.begin(), vSolutionRet.end());
                return true;
            }
            else if (f1 != f2)
            {
                break;
            }
            else if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() <= sizeof(uint256))
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionRet.push_back(make_pair(opcode2, vch1));
            }
            else if (opcode1 != opcode2)
            {
                break;
            }
        }
    }

    vSolutionRet.clear();
    return false;
}


// 根据已匹配出的模板参数在钱包密钥表中找私钥，并编译解锁脚本 scriptSig。
// hash 为 0 时只测试钱包是否拥有所需密钥，IsMine 利用这一行为。
bool Solver(const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet)
{
    scriptSigRet.clear();

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    // P2PK 只需压入签名；P2PKH 还需压入原始公钥供输出脚本核对 HASH160。
    CRITICAL_BLOCK(cs_mapKeys)
    {
        foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
        {
            if (item.first == OP_PUBKEY)
            {
                // Sign
                const valtype& vchPubKey = item.second;
                if (!mapKeys.count(vchPubKey))
                    return false;
                if (hash != 0)
                {
                    vector<unsigned char> vchSig;
                    if (!CKey::Sign(mapKeys[vchPubKey], hash, vchSig))
                        return false;
                    vchSig.push_back((unsigned char)nHashType);
                    scriptSigRet << vchSig;
                }
            }
            else if (item.first == OP_PUBKEYHASH)
            {
                // Sign and give pubkey
                map<uint160, valtype>::iterator mi = mapPubKeys.find(uint160(item.second));
                if (mi == mapPubKeys.end())
                    return false;
                const vector<unsigned char>& vchPubKey = (*mi).second;
                if (!mapKeys.count(vchPubKey))
                    return false;
                if (hash != 0)
                {
                    vector<unsigned char> vchSig;
                    if (!CKey::Sign(mapKeys[vchPubKey], hash, vchSig))
                        return false;
                    vchSig.push_back((unsigned char)nHashType);
                    scriptSigRet << vchSig << vchPubKey;
                }
            }
        }
    }

    return true;
}


// 判断标准输出脚本所需私钥是否存在于当前钱包。
bool IsMine(const CScript& scriptPubKey)
{
    CScript scriptSig;
    return Solver(scriptPubKey, 0, 0, scriptSig);
}


// 从标准脚本提取完整公钥；P2PKH 需用哈希在钱包公钥表中反查。
bool ExtractPubKey(const CScript& scriptPubKey, bool fMineOnly, vector<unsigned char>& vchPubKeyRet)
{
    vchPubKeyRet.clear();

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    CRITICAL_BLOCK(cs_mapKeys)
    {
        foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
        {
            valtype vchPubKey;
            if (item.first == OP_PUBKEY)
            {
                vchPubKey = item.second;
            }
            else if (item.first == OP_PUBKEYHASH)
            {
                map<uint160, valtype>::iterator mi = mapPubKeys.find(uint160(item.second));
                if (mi == mapPubKeys.end())
                    continue;
                vchPubKey = (*mi).second;
            }
            if (!fMineOnly || mapKeys.count(vchPubKey))
            {
                vchPubKeyRet = vchPubKey;
                return true;
            }
        }
    }
    return false;
}


// 从标准 P2PKH 模板提取 20 字节公钥哈希。
bool ExtractHash160(const CScript& scriptPubKey, uint160& hash160Ret)
{
    hash160Ret = 0;

    vector<pair<opcodetype, valtype> > vSolution;
    if (!Solver(scriptPubKey, vSolution))
        return false;

    foreach(PAIRTYPE(opcodetype, valtype)& item, vSolution)
    {
        if (item.first == OP_PUBKEYHASH)
        {
            hash160Ret = uint160(item.second);
            return true;
        }
    }
    return false;
}


// 为 txTo 的一个输入签名：定位 txFrom 中被花费的输出，计算签名摘要，
// 由 Solver 构造 scriptSig，并在无前置脚本时立即执行一次自检。
bool SignSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType, CScript scriptPrereq)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // 摘要脚本由可选前置条件与前序输出锁定脚本组成，不包含尚未生成的签名自身；
    // 验证侧 CHECKSIG 也会从 scriptCode 删除当前签名，保持两边一致。
    uint256 hash = SignatureHash(scriptPrereq + txout.scriptPubKey, txTo, nIn, nHashType);

    if (!Solver(txout.scriptPubKey, hash, nHashType, txin.scriptSig))
        return false;

    txin.scriptSig = scriptPrereq + txin.scriptSig;

    // 无 scriptPrereq 时把解锁/锁定脚本连接起来执行，避免钱包产出无效签名。
    if (scriptPrereq.empty())
        if (!EvalScript(txin.scriptSig + CScript(OP_CODESEPARATOR) + txout.scriptPubKey, txTo, nIn))
            return false;

    return true;
}


// 验证 txTo 的一个输入：先确认 prevout 确实引用给定 txFrom，
// 再以 CODESEPARATOR 连接 scriptSig 和 scriptPubKey，由 EvalScript 判定。
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    return EvalScript(txin.scriptSig + CScript(OP_CODESEPARATOR) + txout.scriptPubKey, txTo, nIn, nHashType);
}
