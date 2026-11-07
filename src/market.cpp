// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// market.cpp — Bitcoin v0.1.3 实验性市场缓存与信誉传播实现
//=============================================================================
//
// 【本文件功能】
//   实现商品广告的内存增删/更新、CReview 的签名验收与落盘，以及 CUser
//   atom 的去重、汇合和沿评价关系传播。
//
// 【在整个系统中的作用】
//   这是一个独立于区块链共识的应用层实验：它借用公钥签名、P2P 地址、
//   序列化和 Berkeley DB，但不改变交易有效性，也不决定链上余额。
//   代码包含明显的原型 TODO 和未完成持久化设计，适合用于理解早期设想。
//
//=============================================================================

#include "headers.h"










//
// Global state variables — 实验性市场的进程内缓存
//

//// later figure out how these are persisted
// 本机发布的商品；原作者已注明此版本尚未解决持久化。
map<uint256, CProduct> mapMyProducts;




map<uint256, CProduct> mapProducts;  // 稳定商品哈希 -> 当前最新广告
CCriticalSection cs_mapProducts;     // 广告可能由多个网络线程并发更新

// 插入新商品，或在同一稳定哈希下接受 sequence 更高的广告版本。
// 注意：CProduct::GetHash() 排除了详情、sequence 和签名等可变字段。
bool AdvertInsert(const CProduct& product)
{
    uint256 hash = product.GetHash();
    bool fNew = false;
    bool fUpdated = false;

    CRITICAL_BLOCK(cs_mapProducts)
    {
        // insert 同时完成“若不存在则加入”和“若存在则取得旧值”。
        pair<map<uint256, CProduct>::iterator, bool> item = mapProducts.insert(make_pair(hash, product));
        CProduct* pproduct = &(*(item.first)).second;
        fNew = item.second;

        // 只有严格更高的序号可覆盖，旧广告/重复广告不会回滚当前版本。
        if (product.nSequence > pproduct->nSequence)
        {
            *pproduct = product;
            fUpdated = true;
        }
    }

    //if (fNew)
    //    NotifyProductAdded(hash);
    //else if (fUpdated)
    //    NotifyProductUpdated(hash);

    return (fNew || fUpdated);
}

void AdvertErase(const CProduct& product)
{
    // 删除依据同一稳定商品哈希，与广告当前 sequence 无关。
    uint256 hash = product.GetHash();
    CRITICAL_BLOCK(cs_mapProducts)
        mapProducts.erase(hash);
    //NotifyProductDeleted(hash);
}



















template<typename T>
unsigned int Union(T& v1, T& v2)
{
    // 求有序集合并集并写回 v1；调用方必须保证两输入已排序。
    // 返回新增元素数，信誉 atom 去重依赖 std::set_union 的这一性质。

    ///// need to check that this is equivalent, then delete this comment
    //vector<unsigned short> vUnion(v1.size() + v2.size());
    //vUnion.erase(set_union(v1.begin(), v1.end(),
    //                       v2.begin(), v2.end(),
    //                       vUnion.begin()),
    //             vUnion.end());

    T vUnion;
    vUnion.reserve(v1.size() + v2.size());
    set_union(v1.begin(), v1.end(),
              v2.begin(), v2.end(),
              back_inserter(vUnion));
    unsigned int nAdded = vUnion.size() - v1.size();
    if (nAdded > 0)
        v1 = vUnion;
    return nAdded;
}

void CUser::AddAtom(unsigned short nAtom, bool fOrigin)
{
    // 已归并或尚待处理的 atom 都算重复；同一标记只影响用户一次。
    if (binary_search(vAtomsIn.begin(), vAtomsIn.end(), nAtom) ||
        find(vAtomsNew.begin(), vAtomsNew.end(), nAtom) != vAtomsNew.end())
        return;

    //// instead of zero atom, should change to free atom that propagates,
    //// limited to lower than a certain value like 5 so conflicts quickly
    // 0 是“不继续传播”的占位 atom；源头创建的 atom 则立即进入输出队列。
    if (nAtom == 0 || fOrigin)
    {
        vector<unsigned short> vTmp(1, nAtom);
        Union(vAtomsIn, vTmp);
        if (fOrigin)
            vAtomsOut.push_back(nAtom);
        return;
    }

    vAtomsNew.push_back(nAtom);

    // 达到阈值（当前为 2），或用户尚无任何输出时，随机挑一个继续流通；
    // 随后把整批新 atom 排序并入 vAtomsIn。
    if (vAtomsNew.size() >= nFlowthroughRate || vAtomsOut.empty())
    {
        // Select atom to flow through to vAtomsOut
        vAtomsOut.push_back(vAtomsNew[GetRand(vAtomsNew.size())]);

        // Merge vAtomsNew into vAtomsIn
        sort(vAtomsNew.begin(), vAtomsNew.end());
        Union(vAtomsIn, vAtomsNew);
        vAtomsNew.clear();
    }
}

bool AddAtomsAndPropagate(uint256 hashUserStart, const vector<unsigned short>& vAtoms, bool fOrigin)
{
    // 双缓冲 map 实现按“波次”扩散：本轮 mapFrom 产生下一轮 mapTo，
    // 无待传播用户时结束。每个用户状态均即时读写 reviews.dat。
    CReviewDB reviewdb;
    map<uint256, vector<unsigned short> > pmapPropagate[2];
    pmapPropagate[0][hashUserStart] = vAtoms;

    for (int side = 0; !pmapPropagate[side].empty(); side = 1 - side)
    {
        map<uint256, vector<unsigned short> >& mapFrom = pmapPropagate[side];
        map<uint256, vector<unsigned short> >& mapTo = pmapPropagate[1 - side];

        for (map<uint256, vector<unsigned short> >::iterator mi = mapFrom.begin(); mi != mapFrom.end(); ++mi)
        {
            const uint256& hashUser = (*mi).first;
            const vector<unsigned short>& vReceived = (*mi).second;

            ///// this would be a lot easier on the database if it put the new atom at the beginning of the list,
            ///// so the change would be right next to the vector size.

            // 不存在的用户记录会保留默认构造的空 CUser。
            CUser user;
            reviewdb.ReadUser(hashUser, user);
            unsigned int nIn = user.vAtomsIn.size();
            unsigned int nNew = user.vAtomsNew.size();
            unsigned int nOut = user.vAtomsOut.size();

            // Add atoms received
            foreach(unsigned short nAtom, vReceived)
                user.AddAtom(nAtom, fOrigin);
            fOrigin = false;

            // 全部为重复 atom 时不写盘，也不产生后续传播。
            if (user.vAtomsIn.size() == nIn && user.vAtomsNew.size() == nNew)
                continue;

            // 只有本次新增到 vAtomsOut 的后缀需要沿每条出边发送。
            if (user.vAtomsOut.size() > nOut)
                foreach(const uint256& hash, user.vLinksOut)
                    mapTo[hash].insert(mapTo[hash].end(), user.vAtomsOut.begin() + nOut, user.vAtomsOut.end());

            // Write back
            if (!reviewdb.WriteUser(hashUser, user))
                return false;
        }
        mapFrom.clear();
    }
    return true;
}






bool CReview::AcceptReview()
{
    // 接收时间是本机内存元数据，不属于评价签名内容。
    nTime = GetTime();

    // 先验签再产生任何数据库副作用。
    if (!CKey::Verify(vchPubKeyFrom, GetSigHash(), vchSig))
        return false;

    CReviewDB reviewdb;

    // 评价按收件人聚合：("reviews", hashTo) -> vector<CReview>。
    vector<CReview> vReviews;
    reviewdb.ReadReviews(hashTo, vReviews);
    vReviews.push_back(*this);
    if (!reviewdb.WriteReviews(hashTo, vReviews))
        return false;

    // 评价同时在信誉图中建立 sender -> recipient 有向边。
    CUser user;
    uint256 hashFrom = Hash(vchPubKeyFrom.begin(), vchPubKeyFrom.end());
    reviewdb.ReadUser(hashFrom, user);
    user.vLinksOut.push_back(hashTo);
    if (!reviewdb.WriteUser(hashFrom, user))
        return false;

    reviewdb.Close();

    // 把评价者已有输出传给收件人；若评价者还没有信誉，则注入不传播的 0。
    vector<unsigned short> vZeroAtom(1, 0);
    if (!AddAtomsAndPropagate(hashTo, user.vAtomsOut.size() ? user.vAtomsOut : vZeroAtom, false))
        return false;

    return true;
}





bool CProduct::CheckSignature()
{
    // GetSigHash() 不包含 vchSig，验证者使用广告携带的卖家公钥。
    return (CKey::Verify(vchPubKeyFrom, GetSigHash(), vchSig));
}

bool CProduct::CheckProduct()
{
    if (!CheckSignature())
        return false;

    // 此入口只接受用于广播/索引的摘要广告，不接受详情和订单表单。
    if (!mapDetails.empty() || !vOrderForm.empty())
        return false;

    // 从 reviews.dat 查询卖家信誉并缓存到仅落盘的 nAtoms 字段。
    CReviewDB reviewdb("r");
    CUser user;
    reviewdb.ReadUser(GetUserHash(), user);
    nAtoms = user.GetAtomCount();
    reviewdb.Close();

    ////// delme, this is now done by AdvertInsert
    //// Store to memory
    //CRITICAL_BLOCK(cs_mapProducts)
    //    mapProducts[GetHash()] = *this;

    return true;
}
