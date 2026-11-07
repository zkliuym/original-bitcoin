// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
//
//=============================================================================
// ui.h — Bitcoin v0.1.3 wxWidgets 界面逻辑声明
//=============================================================================
//
// 【本文件功能】
//   声明从 uibase 生成类派生出的业务窗口类、跨线程事件类型，以及主窗口/
//   转账/地址簿/市场等相关方法。真正实现见 ui.cpp。
//
// 【在整个系统中的作用】
//   1. 用户操作入口：查看余额与交易、发币、管理地址、开关挖矿。
//   2. 把 UI 动作接到核心：SendMoney、StartNode、钱包 map、市场协议等。
//   3. 约定线程边界：后台线程不直接碰控件，通过自定义 wx 事件回投 UI。
//
// 【阅读关系】
//   uibase.h  — FormBuilder 生成的控件外壳与虚事件
//   ui.h      — 本文件：业务状态与处理函数声明
//   ui.cpp    — 实现；应用入口 CMyApp::OnInit2 也在那里
//
//=============================================================================



// 后台线程与 UI 线程之间使用的事件类型。
DECLARE_EVENT_TYPE(wxEVT_CROSSTHREADCALL, -1)
DECLARE_EVENT_TYPE(wxEVT_REPLY1, -1)
DECLARE_EVENT_TYPE(wxEVT_REPLY2, -1)
DECLARE_EVENT_TYPE(wxEVT_REPLY3, -1)
DECLARE_EVENT_TYPE(wxEVT_TABLEADDED, -1)
DECLARE_EVENT_TYPE(wxEVT_TABLEUPDATED, -1)
DECLARE_EVENT_TYPE(wxEVT_TABLEDELETED, -1)

enum
{
    // 通用跨线程调用的操作编号；订单分支在这个版本中仍是预留接口。
    UICALL_ADDORDER = 1,
    UICALL_UPDATEORDER,
};
// 各窗口共用的 UI 辅助入口：文本全选、时间/状态格式化、跨线程唤醒及退出。
extern void HandleCtrlA(wxKeyEvent& event);
extern string DateTimeStr(int64 nTime);
extern string FormatTxStatus(const CWalletTx& wtx);
extern void CrossThreadCall(int nID, void* pdata);
extern void MainFrameRepaint();
extern void Shutdown(void* parg);






// 钱包主窗口：展示余额和交易列表，并作为发送、地址簿、设置及挖矿开关的入口。
class CMainFrame : public CMainFrameBase
{
protected:
    // wxWidgets 事件入口：窗口生命周期、菜单/工具栏和交易列表交互。
    void OnClose(wxCloseEvent& event);
    void OnMouseEvents(wxMouseEvent& event);
    void OnKeyDown(wxKeyEvent& event) { HandleCtrlA(event); }
    void OnIdle(wxIdleEvent& event);
    void OnPaint(wxPaintEvent& event);
    void OnPaintListCtrl(wxPaintEvent& event);
    void OnMenuFileExit(wxCommandEvent& event);
    void OnMenuOptionsGenerate(wxCommandEvent& event);
    void OnMenuOptionsOptions(wxCommandEvent& event);
    void OnMenuHelpAbout(wxCommandEvent& event);
    void OnButtonSend(wxCommandEvent& event);
    void OnButtonAddressBook(wxCommandEvent& event);
    void OnSetFocusAddress(wxFocusEvent& event);
    void OnMouseEventsAddress(wxMouseEvent& event);
    void OnButtonCopy(wxCommandEvent& event);
    void OnButtonChange(wxCommandEvent& event);
    void OnListColBeginDrag(wxListEvent& event);
    void OnListItemActivatedAllTransactions(wxListEvent& event);
    void OnListItemActivatedProductsSent(wxListEvent& event);
    void OnListItemActivatedOrdersSent(wxListEvent& event);
    void OnListItemActivatedOrdersReceived(wxListEvent& event);
	
public:
    // 创建窗口时初始化工具栏、列表列、状态栏、默认收款地址和钱包交易。
    CMainFrame(wxWindow* parent);
    ~CMainFrame();

    // 列表刷新状态。耗时重建被安排到空闲事件中，避免阻塞普通事件处理。
    bool fRefreshListCtrl;
    bool fRefreshListCtrlRunning;
    bool fOnSetFocusAddress;
    CBlockIndex* pindexBestLast;
    set<uint256> setUnmaturedDisplayed;

    // 接收后台线程投递到主窗口的命令。
    void OnCrossThreadCall(wxCommandEvent& event);
    // 新增或更新交易列表的一行；隐藏列保存排序键和交易哈希。
    void InsertLine(bool fNew, int nIndex, uint256 hashKey, string strSort, const wxString& str1, const wxString& str2, const wxString& str3, const wxString& str4, const wxString& str5);
    // 将钱包交易解释成“状态/日期/说明/收支”等 UI 字段。
    void InsertTransaction(const CWalletTx& wtx, bool fNew, int nIndex=-1);
    // 请求完整重建列表；实际工作在 OnIdle 中执行。
    void RefreshListCtrl();
    // 仅刷新可见交易的确认状态。
    void RefreshStatus();
};




// 交易详情对话框：把交易来源、去向、金额、手续费和调试信息渲染成 HTML。
class CTxDetailsDialog : public CTxDetailsDialogBase
{
protected:
    // Event handlers
    void OnButtonOK(wxCommandEvent& event);

public:
    /** Constructor */
    CTxDetailsDialog(wxWindow* parent, CWalletTx wtx);

    // 保留被查看交易的副本。
    CWalletTx wtx;
};



// 选项对话框：本版本主要用于编辑并持久化默认交易费。
class COptionsDialog : public COptionsDialogBase
{
protected:
    // Event handlers
    void OnKillFocusTransactionFee(wxFocusEvent& event);
    void OnButtonOK(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);

public:
    /** Constructor */
    COptionsDialog(wxWindow* parent);
};



// 关于对话框：显示客户端版本与项目说明。
class CAboutDialog : public CAboutDialogBase
{
protected:
    // Event handlers
    void OnButtonOK(wxCommandEvent& event);

public:
    /** Constructor */
    CAboutDialog(wxWindow* parent);
};



// 发送入口：校验金额，并按目标格式分流到普通 Bitcoin 地址或旧式 IP 支付。
class CSendDialog : public CSendDialogBase
{
protected:
    // Event handlers
    void OnKeyDown(wxKeyEvent& event) { HandleCtrlA(event); }
    void OnTextAddress(wxCommandEvent& event);
    void OnKillFocusAmount(wxFocusEvent& event);
    void OnButtonAddressBook(wxCommandEvent& event);
    void OnButtonPaste(wxCommandEvent& event);
    void OnButtonSend(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);
	
public:
    /** Constructor */
    CSendDialog(wxWindow* parent, const wxString& strAddress="");
};



// IP 支付进度对话框：后台连接收款方，执行 checkorder/submitorder 握手并付款。
// 它刻意不挂在父窗口生命周期下，取消后也要等待工作线程安全退出。
class CSendingDialog : public CSendingDialogBase
{
public:
    // Event handlers
    void OnClose(wxCloseEvent& event);
    void OnButtonOK(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);
    void OnPaint(wxPaintEvent& event);
	
public:
    /** Constructor */
    CSendingDialog(wxWindow* parent, const CAddress& addrIn, int64 nPriceIn, const CWalletTx& wtxIn);
    ~CSendingDialog();

    // 跨 UI/工作线程共享的传输状态。
    CAddress addr;
    int64 nPrice;
    CWalletTx wtx;
    wxDateTime start;
    string strStatus;
    bool fCanCancel;
    bool fAbort;
    bool fSuccess;
    bool fUIDone;
    bool fWorkDone;

    // 根据 UI 与工作线程是否都已结束，隐藏或最终销毁窗口。
    void Close();
    // 安排 UI 重绘并报告进度/错误。
    void Repaint();
    bool Status();
    bool Status(const string& str);
    bool Error(const string& str);
    // 工作线程主流程：连接、checkorder、建交易、submitorder、广播。
    void StartTransfer();
    // checkorder 返回收款脚本后创建并提交付款交易。
    void OnReply2(CDataStream& vRecv);
    // submitorder 的最终确认回调。
    void OnReply3(CDataStream& vRecv);
};

// C 风格线程/网络回调跳板，把 void* 上下文还原为 CSendingDialog。
void SendingDialogStartTransfer(void* parg);
void SendingDialogOnReply2(void* parg, CDataStream& vRecv);
void SendingDialogOnReply3(void* parg, CDataStream& vRecv);



// “你的地址”对话框：只列出钱包自身公钥对应的地址，可生成新密钥或改标签。
class CYourAddressDialog : public CYourAddressDialogBase
{
protected:
    // Event handlers
    void OnListEndLabelEdit(wxListEvent& event);
    void OnListItemSelected(wxListEvent& event);
    void OnListItemActivated(wxListEvent& event);
    void OnButtonRename(wxCommandEvent& event);
    void OnButtonNew(wxCommandEvent& event);
    void OnButtonCopy(wxCommandEvent& event);
    void OnButtonOK(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);
    void OnClose(wxCloseEvent& event);

public:
    /** Constructor */
    CYourAddressDialog(wxWindow* parent);
    CYourAddressDialog(wxWindow* parent, const string& strInitSelected);

    // 返回当前选中的自有地址。
    wxString GetAddress();
};



// 外部联系人地址簿：维护非本钱包地址，也可在发送流程中充当地址选择器。
class CAddressBookDialog : public CAddressBookDialogBase
{
protected:
    // Event handlers
    void OnListEndLabelEdit(wxListEvent& event);
    void OnListItemSelected(wxListEvent& event);
    void OnListItemActivated(wxListEvent& event);
    void OnButtonEdit(wxCommandEvent& event);
    void OnButtonDelete(wxCommandEvent& event);
    void OnButtonNew(wxCommandEvent& event);
    void OnButtonCopy(wxCommandEvent& event);
    void OnButtonOK(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);
    void OnClose(wxCloseEvent& event);

public:
    /** Constructor */
    CAddressBookDialog(wxWindow* parent, const wxString& strInitSelected, bool fSendingIn);

    // fSending 决定双击是“选中并返回”还是“编辑条目”。
    bool fSending;
    wxString GetAddress();
};



// 早期内置市场的商品搜索窗口：按类别/关键字筛选并按工作量权重排序。
class CProductsDialog : public CProductsDialogBase
{
protected:
    // Event handlers
    void OnKeyDown(wxKeyEvent& event) { HandleCtrlA(event); }
    void OnCombobox(wxCommandEvent& event);
    void OnButtonSearch(wxCommandEvent& event);
    void OnListItemActivated(wxListEvent& event);

public:
    /** Constructor */
    CProductsDialog(wxWindow* parent);

    // 与列表行对应的商品数据。
    vector<CProduct> m_vProduct;
};



// 商品编辑器：编辑商品说明及最多 20 个动态订单字段，签名后广播商品广告。
class CEditProductDialog : public CEditProductDialogBase
{
protected:
    // Event handlers
    void OnKeyDown(wxKeyEvent& event) { HandleCtrlA(event); }
    void OnButtonDel0(wxCommandEvent& event);
    void OnButtonDel1(wxCommandEvent& event);
    void OnButtonDel2(wxCommandEvent& event);
    void OnButtonDel3(wxCommandEvent& event);
    void OnButtonDel4(wxCommandEvent& event);
    void OnButtonDel5(wxCommandEvent& event);
    void OnButtonDel6(wxCommandEvent& event);
    void OnButtonDel7(wxCommandEvent& event);
    void OnButtonDel8(wxCommandEvent& event);
    void OnButtonDel9(wxCommandEvent& event);
    void OnButtonDel10(wxCommandEvent& event);
    void OnButtonDel11(wxCommandEvent& event);
    void OnButtonDel12(wxCommandEvent& event);
    void OnButtonDel13(wxCommandEvent& event);
    void OnButtonDel14(wxCommandEvent& event);
    void OnButtonDel15(wxCommandEvent& event);
    void OnButtonDel16(wxCommandEvent& event);
    void OnButtonDel17(wxCommandEvent& event);
    void OnButtonDel18(wxCommandEvent& event);
    void OnButtonDel19(wxCommandEvent& event);
    void OnButtonAddField(wxCommandEvent& event);
    void OnButtonSend(wxCommandEvent& event);
    void OnButtonPreview(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);

public:
    /** Constructor */
    CEditProductDialog(wxWindow* parent);

    // 将生成器产生的 20 组独立控件整理成数组，便于统一增删和序列化。
    enum { FIELDS_MAX = 20 };
    wxTextCtrl* m_textCtrlLabel[FIELDS_MAX];
    wxTextCtrl* m_textCtrlField[FIELDS_MAX];
    wxButton*   m_buttonDel[FIELDS_MAX];

    // 动态字段的布局、显示、删除，以及 CProduct 与控件之间的双向转换。
    void LayoutAll();
    void ShowLine(int i, bool fShow=true);
    void OnButtonDel(wxCommandEvent& event, int n);
    void SetProduct(const CProduct& productIn);
    void GetProduct(CProduct& product);

};



// 商品查看/下单窗口：先显示摘要，异步获取详情，再动态构造订单表单。
class CViewProductDialog : public CViewProductDialogBase
{
protected:
    // Event handlers
    void OnButtonSubmitForm(wxCommandEvent& event);
    void OnButtonCancelForm(wxCommandEvent& event);
    void OnButtonBack(wxCommandEvent& event);
    void OnButtonNext(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);

public:
    /** Constructor */
    CViewProductDialog(wxWindow* parent, const CProduct& productIn);
    ~CViewProductDialog();

    // 当前商品及按订单模板动态创建的控件。
    CProduct product;
    enum { FIELDS_MAX = 20 };
    wxStaticText* m_staticTextLabel[FIELDS_MAX];
    wxTextCtrl*   m_textCtrlField[FIELDS_MAX];
    wxChoice*     m_choiceField[FIELDS_MAX];

    // 将表单值装入订单交易；UpdateProductDisplay 同时构造详情和表单页面。
    void GetOrder(CWalletTx& order);
    void UpdateProductDisplay(bool fDetails);
    void OnReply1(wxCommandEvent& event);
};



// 订单查看窗口：以 HTML 展示订单价格、状态和表单字段。
class CViewOrderDialog : public CViewOrderDialogBase
{
protected:
    // Event handlers
    void OnButtonOK(wxCommandEvent& event);

public:
    /** Constructor */
    CViewOrderDialog(wxWindow* parent, CWalletTx order, bool fReceived);

    // 标记订单属于卖方收到，还是买方发出。
    bool fReceived;
};



// 评价编辑窗口：收集星级和文字，签名、接受并向网络广播评价。
class CEditReviewDialog : public CEditReviewDialogBase
{
protected:
    // Event handlers
    void OnKeyDown(wxKeyEvent& event) { HandleCtrlA(event); }
    void OnButtonSubmit(wxCommandEvent& event);
    void OnButtonCancel(wxCommandEvent& event);

public:
    /** Constructor */
    CEditReviewDialog(wxWindow* parent);

    // 从控件组装 CReview。
    void GetReview(CReview& review);
};



// 通用的一到两字段文本输入框，供地址新增、重命名和编辑复用。
class CGetTextFromUserDialog : public CGetTextFromUserDialogBase
{
protected:
    // Event handlers
    void OnButtonOK(wxCommandEvent& event)     { EndModal(true); }
    void OnButtonCancel(wxCommandEvent& event) { EndModal(false); }
    void OnClose(wxCloseEvent& event)          { EndModal(false); }

    void OnKeyDown(wxKeyEvent& event)
    {
        if (event.GetKeyCode() == '\r' || event.GetKeyCode() == WXK_NUMPAD_ENTER)
            EndModal(true);
        else
            HandleCtrlA(event);
    }

public:
    /** Constructor */
    CGetTextFromUserDialog(wxWindow* parent,
                           const string& strCaption,
                           const string& strMessage1,
                           const string& strValue1="",
                           const string& strMessage2="",
                           const string& strValue2="") : CGetTextFromUserDialogBase(parent, wxID_ANY, strCaption)
    {
        m_staticTextMessage1->SetLabel(strMessage1);
        m_textCtrl1->SetValue(strValue1);
        if (!strMessage2.empty())
        {
            m_staticTextMessage2->Show(true);
            m_staticTextMessage2->SetLabel(strMessage2);
            m_textCtrl2->Show(true);
            m_textCtrl2->SetValue(strValue2);
            SetSize(wxDefaultCoord, 180);
        }
    }

    // 单字段调用用 GetValue；双字段调用使用 GetValue1/GetValue2。
    string GetValue()  { return (string)m_textCtrl1->GetValue(); }
    string GetValue1() { return (string)m_textCtrl1->GetValue(); }
    string GetValue2() { return (string)m_textCtrl2->GetValue(); }
};





