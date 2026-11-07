// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// base58.h — Base58Check 与早期 Bitcoin 地址编码
//=============================================================================
//
// 【本文件功能】
//   在字节串与易抄写的 Base58 文本之间转换；Base58Check 追加/校验双 SHA256
//   的前 4 字节；并把 160 位公钥哈希包装为主网地址。
//
// 【在整个系统中的作用】
//   钱包和界面用这里的函数显示、输入、验证 Bitcoin 地址。地址不是公钥本身，
//   而是“版本字节 + Hash160 + 校验和”的可读编码。
//
// 【阅读提示】
//   原始 Base58 转换使用 CBigNum 做除 58/乘 58；输入前导 0 字节映射为字符 '1'。
//   本 v0.1.3 代码只有 ADDRESSVERSION=0 的主网 P2PKH 风格地址。
//
//=============================================================================


//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Doubleclicking selects the whole number as one word if it's all alphanumeric.
//


// 去掉易混淆字符 0/O/I/l 后的 58 字符字母表；索引即对应数值。
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


// 把高位在前的任意字节串编码成 Base58，并显式保留所有前导零。
inline string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to string
    string str;
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
            throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getulong();
        str += pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];

    // Convert little endian string to big endian
    reverse(str.begin(), str.end());
    return str;
}

inline string EncodeBase58(const vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

// 解析 Base58 文本为高位在前的字节串；拒绝非字母表字符（末尾空白除外）。
inline bool DecodeBase58(const char* psz, vector<unsigned char>& vchRet)
{
    CAutoBN_CTX pctx;
    vchRet.clear();
    CBigNum bn58 = 58;
    CBigNum bn = 0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(pszBase58, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return false;
            break;
        }
        bnChar.setulong(p1 - pszBase58);
        if (!BN_mul(&bn, &bn, &bn58, pctx))
            throw bignum_error("DecodeBase58 : BN_mul failed");
        bn += bnChar;
    }

    // Get bignum as little endian data
    vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}

inline bool DecodeBase58(const string& str, vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}





// 在负载末尾追加 double-SHA256 的前 4 字节，再进行 Base58 编码。
inline string EncodeBase58Check(const vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

// 解码并验证 4 字节校验和；失败时清空输出，避免调用者误用未验证数据。
inline bool DecodeBase58Check(const char* psz, vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

inline bool DecodeBase58Check(const string& str, vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}






// 主网普通地址版本字节；编码后这类地址通常以字符 '1' 开头。
static const unsigned char ADDRESSVERSION = 0;

// 将 20 字节公钥哈希封装为版本 0 的 Base58Check 地址。
inline string Hash160ToAddress(uint160 hash160)
{
    // add 1-byte version number to the front
    vector<unsigned char> vch(1, ADDRESSVERSION);
    vch.insert(vch.end(), UBEGIN(hash160), UEND(hash160));
    return EncodeBase58Check(vch);
}

// 验证地址、检查长度与版本，并取回其中的 160 位公钥哈希。
inline bool AddressToHash160(const char* psz, uint160& hash160Ret)
{
    vector<unsigned char> vch;
    if (!DecodeBase58Check(psz, vch))
        return false;
    if (vch.empty())
        return false;
    unsigned char nVersion = vch[0];
    if (vch.size() != sizeof(hash160Ret) + 1)
        return false;
    memcpy(&hash160Ret, &vch[1], sizeof(hash160Ret));
    return (nVersion <= ADDRESSVERSION);
}

inline bool AddressToHash160(const string& str, uint160& hash160Ret)
{
    return AddressToHash160(str.c_str(), hash160Ret);
}

// 地址格式与校验和的轻量验证入口。
inline bool IsValidBitcoinAddress(const char* psz)
{
    uint160 hash160;
    return AddressToHash160(psz, hash160);
}

inline bool IsValidBitcoinAddress(const string& str)
{
    return IsValidBitcoinAddress(str.c_str());
}




// 公钥先做 RIPEMD160(SHA256(pubkey))，再编码为可显示地址。
inline string PubKeyToAddress(const vector<unsigned char>& vchPubKey)
{
    return Hash160ToAddress(Hash160(vchPubKey));
}
