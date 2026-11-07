// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// key.h — secp256k1 密钥与 ECDSA 签名封装
//=============================================================================
//
// 【本文件功能】
//   封装 OpenSSL EC_KEY，完成密钥生成、私钥/公钥导入导出，以及对 uint256
//   摘要的 ECDSA 签名和验签。
//
// 【在整个系统中的作用】
//   钱包用 CKey 生成并保存私钥、派生公钥；交易签名由私钥产生，脚本验证阶段
//   再用公钥验证，从而证明花费者有权使用对应输出。
//
// 【阅读提示】
//   曲线固定为 secp256k1。CPrivKey 是带 secure_allocator 的 DER 私钥字节串；
//   公钥与签名也使用 OpenSSL 编码。这里接收的是已经算好的 256 位摘要，
//   不负责交易序列化或 SignatureHash 的计算。
//
//=============================================================================


// secp160k1
// const unsigned int PRIVATE_KEY_SIZE = 192;
// const unsigned int PUBLIC_KEY_SIZE  = 41;
// const unsigned int SIGNATURE_SIZE   = 48;
//
// secp192k1
// const unsigned int PRIVATE_KEY_SIZE = 222;
// const unsigned int PUBLIC_KEY_SIZE  = 49;
// const unsigned int SIGNATURE_SIZE   = 57;
//
// secp224k1
// const unsigned int PRIVATE_KEY_SIZE = 250;
// const unsigned int PUBLIC_KEY_SIZE  = 57;
// const unsigned int SIGNATURE_SIZE   = 66;
//
// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push



// 椭圆曲线对象分配、复制或编码失败时使用的异常。
class key_error : public std::runtime_error
{
public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};


// secure_allocator is defined is serialize.h
// 私钥序列化字节；安全分配器会在释放内存前覆写内容，降低密钥残留风险。
typedef vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;



// 单个 secp256k1 密钥对象的 RAII 封装，同时可承载私钥+公钥或仅公钥。
class CKey
{
protected:
    // OpenSSL 椭圆曲线密钥句柄，由本对象独占并在析构时释放。
    EC_KEY* pkey;

public:
    CKey()
    {
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (pkey == NULL)
            throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
    }

    CKey(const CKey& b)
    {
        pkey = EC_KEY_dup(b.pkey);
        if (pkey == NULL)
            throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
    }

    CKey& operator=(const CKey& b)
    {
        if (!EC_KEY_copy(pkey, b.pkey))
            throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
        return (*this);
    }

    ~CKey()
    {
        EC_KEY_free(pkey);
    }

    // 使用 OpenSSL 随机源生成新的 secp256k1 私钥及对应公钥。
    void MakeNewKey()
    {
        if (!EC_KEY_generate_key(pkey))
            throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
    }

    // 从 OpenSSL DER 编码恢复私钥；成功后密钥对象可用于签名。
    bool SetPrivKey(const CPrivKey& vchPrivKey)
    {
        const unsigned char* pbegin = &vchPrivKey[0];
        if (!d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
            return false;
        return true;
    }

    // 导出 OpenSSL DER 私钥，返回值使用安全内存分配器。
    CPrivKey GetPrivKey() const
    {
        unsigned int nSize = i2d_ECPrivateKey(pkey, NULL);
        if (!nSize)
            throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
        CPrivKey vchPrivKey(nSize, 0);
        unsigned char* pbegin = &vchPrivKey[0];
        if (i2d_ECPrivateKey(pkey, &pbegin) != nSize)
            throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
        return vchPrivKey;
    }

    // 从 SEC1 八位组格式导入公钥，用于仅验签场景。
    bool SetPubKey(const vector<unsigned char>& vchPubKey)
    {
        const unsigned char* pbegin = &vchPubKey[0];
        if (!o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.size()))
            return false;
        return true;
    }

    // 导出 SEC1 公钥字节；本版本通常使用未压缩的 65 字节公钥。
    vector<unsigned char> GetPubKey() const
    {
        unsigned int nSize = i2o_ECPublicKey(pkey, NULL);
        if (!nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
        vector<unsigned char> vchPubKey(nSize, 0);
        unsigned char* pbegin = &vchPubKey[0];
        if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
        return vchPubKey;
    }

    // 用当前私钥签署 32 字节摘要，输出 DER 编码的 ECDSA 签名。
    bool Sign(uint256 hash, vector<unsigned char>& vchSig)
    {
        vchSig.clear();
        unsigned char pchSig[10000];
        unsigned int nSize = 0;
        if (!ECDSA_sign(0, (unsigned char*)&hash, sizeof(hash), pchSig, &nSize, pkey))
            return false;
        vchSig.resize(nSize);
        memcpy(&vchSig[0], pchSig, nSize);
        return true;
    }

    // 用当前公钥验证 DER ECDSA 签名；OpenSSL 仅返回 1 时才视为有效。
    bool Verify(uint256 hash, const vector<unsigned char>& vchSig)
    {
        // -1 = error, 0 = bad sig, 1 = good
        if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
            return false;
        return true;
    }

    // 便捷接口：临时导入给定私钥后签名。
    static bool Sign(const CPrivKey& vchPrivKey, uint256 hash, vector<unsigned char>& vchSig)
    {
        CKey key;
        if (!key.SetPrivKey(vchPrivKey))
            return false;
        return key.Sign(hash, vchSig);
    }

    // 便捷接口：临时导入给定公钥后验签。
    static bool Verify(const vector<unsigned char>& vchPubKey, uint256 hash, const vector<unsigned char>& vchSig)
    {
        CKey key;
        if (!key.SetPubKey(vchPubKey))
            return false;
        return key.Verify(hash, vchSig);
    }
};
