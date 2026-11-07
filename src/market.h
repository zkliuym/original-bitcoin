// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// market.h — Bitcoin v0.1.3 实验性市场与评价信誉模型
//=============================================================================
//
// 【本文件功能】
//   定义商品广告 CProduct、评价 CReview、信誉传播节点 CUser，以及广告缓存和
//   “atom（信誉标记）”传播入口。该功能是早期原型，并非比特币转账共识的一部分。
//
// 【在整个系统中的作用】
//   - 市场层：卖家签名商品摘要，节点在内存 mapProducts 中保存较新的广告版本。
//   - 评价层：评价经公钥签名后写入 reviews.dat，并建立评价者到收件人的关系。
//   - 信誉层：小整数 atom 沿评价链接传播，作为非常早期的信誉/防女巫实验。
//   这些对象会使用网络/磁盘序列化，但不会参与区块、交易验证或工作量证明。
//
// 【阅读提示】
//   本原型存在未完成痕迹（例如 market.dat 尚无专用接口、mapMyProducts 未持久化）；
//   阅读重点应放在历史设计思路，不应将其视为成熟或安全的现代市场协议。
//
//=============================================================================

class CUser;
class CReview;
class CProduct;

// 每积累两个待处理 atom，就随机选一个向外传播。
static const unsigned int nFlowthroughRate = 2;




bool AdvertInsert(const CProduct& product);  // 插入广告，或用更高 sequence 更新
void AdvertErase(const CProduct& product);  // 按稳定商品哈希移除广告
bool AddAtomsAndPropagate(uint256 hashUserStart, const vector<unsigned short>& vAtoms, bool fOrigin);








// CUser：信誉传播图中的一个用户节点，以用户公钥 Hash 标识并存入 reviews.dat。
// vAtomsIn 是已吸收标记，vAtomsNew 是尚待汇合标记，vAtomsOut 是已向外发送标记；
// vLinksOut 记录该用户评价过的收件人，决定信誉传播方向。
class CUser
{
public:
    vector<unsigned short> vAtomsIn;  // 已接收并归并（保持排序）的 atom
    vector<unsigned short> vAtomsNew; // 新到达、等待达到流通阈值的 atom
    vector<unsigned short> vAtomsOut; // 已选中并可沿链接继续传播的 atom
    vector<uint256> vLinksOut;        // 从本用户指向被评价用户的有向边

    CUser()
    {
    }

    IMPLEMENT_SERIALIZE
    (
        // 取哈希时省略流版本；其余场景先记录版本，再记录完整传播状态。
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vAtomsIn);
        READWRITE(vAtomsNew);
        READWRITE(vAtomsOut);
        READWRITE(vLinksOut);
    )

    void SetNull()
    {
        vAtomsIn.clear();
        vAtomsNew.clear();
        vAtomsOut.clear();
        vLinksOut.clear();
    }

    uint256 GetHash() const { return SerializeHash(*this); }


    // 此原型用已吸收 + 待处理数量作为卖家的信誉计数。
    int GetAtomCount() const
    {
        return (vAtomsIn.size() + vAtomsNew.size());
    }

    // 去重并归并一个 atom；必要时挑选新 atom 加入 vAtomsOut。
    void AddAtom(unsigned short nAtom, bool fOrigin);
};







// CReview：从 vchPubKeyFrom 指向 hashTo 的签名评价。
// mapValue 承载自由格式评价字段；nTime/nAtoms 仅供运行时使用，不参与序列化。
class CReview
{
public:
    int nVersion;                         // 评价格式版本
    uint256 hashTo;                       // 被评价用户哈希
    map<string, string> mapValue;         // 评价正文/属性
    vector<unsigned char> vchPubKeyFrom;  // 评价者公钥
    vector<unsigned char> vchSig;         // 对 GetSigHash() 的签名

    // memory only：不写入网络或 reviews.dat
    unsigned int nTime;                   // 本地接收时间
    int nAtoms;                           // 本地计算的信誉辅助值


    CReview()
    {
        nVersion = 1;
        hashTo = 0;
        nTime = 0;
        nAtoms = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        // 磁盘中 hashTo 已体现在 ("reviews", hashTo) 键上，避免重复保存。
        if (!(nType & SER_DISK))
            READWRITE(hashTo);
        READWRITE(mapValue);
        READWRITE(vchPubKeyFrom);
        // 计算签名哈希时排除签名本身，避免自引用。
        if (!(nType & SER_GETHASH))
            READWRITE(vchSig);
    )

    uint256 GetHash() const { return SerializeHash(*this); }
    uint256 GetSigHash() const { return SerializeHash(*this, SER_GETHASH|SER_SKIPSIG); }
    uint256 GetUserHash() const { return Hash(vchPubKeyFrom.begin(), vchPubKeyFrom.end()); }


    // 验签、追加评价、建立信誉链接，并触发 atom 传播。
    bool AcceptReview();
};







// CProduct：卖家签名的商品广告。
// GetHash() 在 SER_GETHASH 下只覆盖稳定摘要字段，使详情和 sequence 更新仍映射到
// 同一商品标识；GetSigHash() 同时排除签名，用于签名/验签。
class CProduct
{
public:
    int nVersion;                              // 广告格式版本
    CAddress addr;                             // 卖家可联系的网络地址
    map<string, string> mapValue;              // 参与商品稳定哈希的摘要字段
    map<string, string> mapDetails;            // 详细描述（摘要广告中必须为空）
    vector<pair<string, string> > vOrderForm;  // 订单表单字段
    unsigned int nSequence;                    // 同一商品广告的更新序号
    vector<unsigned char> vchPubKeyFrom;       // 卖家公钥
    vector<unsigned char> vchSig;              // 卖家签名

    // disk only：落盘时缓存卖家信誉计数
    int nAtoms;

    // memory only：记录从哪些对端收到该广告
    set<unsigned int> setSources;

    CProduct()
    {
        nVersion = 1;
        nAtoms = 0;
        nSequence = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(addr);
        READWRITE(mapValue);
        // 商品哈希只取稳定摘要；普通网络/磁盘编码才携带可变详情和更新序号。
        if (!(nType & SER_GETHASH))
        {
            READWRITE(mapDetails);
            READWRITE(vOrderForm);
            READWRITE(nSequence);
        }
        READWRITE(vchPubKeyFrom);
        if (!(nType & SER_GETHASH))
            READWRITE(vchSig);
        // nAtoms 是本地派生缓存，不在节点间传播。
        if (nType & SER_DISK)
            READWRITE(nAtoms);
    )

    uint256 GetHash() const { return SerializeHash(*this); }
    uint256 GetSigHash() const { return SerializeHash(*this, SER_GETHASH|SER_SKIPSIG); }
    uint256 GetUserHash() const { return Hash(vchPubKeyFrom.begin(), vchPubKeyFrom.end()); }


    bool CheckSignature(); // 用卖家公钥验证广告签名
    bool CheckProduct();   // 验签、检查摘要形式并查询卖家信誉
};








extern map<uint256, CProduct> mapProducts;    // 商品哈希 -> 当前已知最新广告
extern CCriticalSection cs_mapProducts;       // 保护 mapProducts
extern map<uint256, CProduct> mapMyProducts;  // 本机商品；此版本尚未持久化
