#include "winsec.h"

winsec::winsec() {
    privegies = { {1,SE_ASSIGNPRIMARYTOKEN_NAME},{2,SE_AUDIT_NAME},{3,SE_BACKUP_NAME },{4,SE_CHANGE_NOTIFY_NAME},
        {5,SE_CREATE_GLOBAL_NAME},{6,SE_CREATE_PAGEFILE_NAME},{7,SE_CREATE_PERMANENT_NAME},{7,SE_CREATE_SYMBOLIC_LINK_NAME},
        {8,SE_CREATE_TOKEN_NAME},{10,SE_DEBUG_NAME},{11,SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME},{12,SE_ENABLE_DELEGATION_NAME},
        {13,SE_IMPERSONATE_NAME},{14,SE_INC_BASE_PRIORITY_NAME},{15,SE_INCREASE_QUOTA_NAME},{16,SE_INC_WORKING_SET_NAME},
        {17,SE_LOAD_DRIVER_NAME},{18,SE_LOCK_MEMORY_NAME},{19,SE_MACHINE_ACCOUNT_NAME},{20,SE_MANAGE_VOLUME_NAME},
        {21,SE_PROF_SINGLE_PROCESS_NAME},{22,SE_RELABEL_NAME},{23,SE_REMOTE_SHUTDOWN_NAME},{24,SE_RESTORE_NAME},{25,SE_SECURITY_NAME},
        {26,SE_SHUTDOWN_NAME},{27,SE_SYNC_AGENT_NAME},{28,SE_SYSTEM_ENVIRONMENT_NAME},{29,SE_SYSTEM_PROFILE_NAME},{30,SE_SYSTEMTIME_NAME},
        {31,SE_TAKE_OWNERSHIP_NAME},{32,SE_TCB_NAME},{33,SE_TIME_ZONE_NAME},{34,SE_TRUSTED_CREDMAN_ACCESS_NAME},{35,SE_UNDOCK_NAME},{36,SE_UNSOLICITED_INPUT_NAME} };
}

std::string winsec::get_error(DWORD error) {
    std::string message = std::system_category().message(error);
    return message;
}

bool winsec::print_result(NET_API_STATUS nStatus, std::string result_message) {
    if (nStatus != NERR_Success) {
        std::cout << "\t" << get_error(nStatus) << " " << nStatus << std::endl;
        return false;
    }
    else if (result_message!="")
        std::cout << result_message << std::endl;  
    return true;
}

bool winsec::add_user(const wchar_t* server_name,const wchar_t* user_name, const wchar_t* password,
    DWORD user_priv, const wchar_t* home_dir, const wchar_t* comment, DWORD flags,
    const wchar_t* script_path)
{
    USER_INFO_1* ui = new USER_INFO_1;
    DWORD dwError = 0;    
    
    ui->usri1_name = (LPWSTR)user_name;
    ui->usri1_password = (LPWSTR)password;
    ui->usri1_priv = USER_PRIV_ADMIN;//user_priv;
    ui->usri1_home_dir = (LPWSTR)home_dir;
    ui->usri1_comment = (LPWSTR)comment;
    ui->usri1_flags = flags;
    ui->usri1_script_path = (LPWSTR)script_path;
    
    NET_API_STATUS nStatus = NetUserAdd((LPCWSTR)server_name, 1, (LPBYTE)ui, &dwError);
    delete ui;
    return print_result(nStatus, "User has been successfully added");
}

bool winsec::change_user(const wchar_t* server_name, const wchar_t* user_name, const wchar_t* password,
    DWORD user_priv, const wchar_t* home_dir, const wchar_t* comment, DWORD flags,
    const wchar_t* script_path)
{
    USER_INFO_1* ui = new USER_INFO_1;
    DWORD dwError = 0;

    ui->usri1_name = (LPWSTR)user_name;
    ui->usri1_password = (LPWSTR)password;
    ui->usri1_priv = USER_PRIV_ADMIN;//user_priv;
    ui->usri1_home_dir = (LPWSTR)home_dir;
    ui->usri1_comment = (LPWSTR)comment;
    ui->usri1_flags = flags;
    ui->usri1_script_path = (LPWSTR)script_path;

    NET_API_STATUS nStatus = NetUserSetInfo((LPCWSTR)server_name, user_name, 1, (LPBYTE)ui, &dwError);
    delete ui;
    return print_result(nStatus, "User's options have been successfully changed");
}

bool winsec::del_user(const wchar_t* server_name,const wchar_t* user_name)
{
    NET_API_STATUS nStatus = NetUserDel(server_name, user_name);
    return print_result(nStatus, "User has been successfully deleted");
}

bool winsec::add_global_group(const wchar_t* server_name,const wchar_t* group_name, const wchar_t*comment)
{
    std::unique_ptr<GROUP_INFO_1> gi1= std::make_unique<GROUP_INFO_1>();
    gi1->grpi1_name = (LPWSTR)group_name;
    gi1->grpi1_comment = (LPWSTR)comment;

    DWORD dwError = 0;
    NET_API_STATUS nStatus = NetGroupAdd(server_name, 1, (PBYTE)gi1.get(), &dwError);
    return print_result(nStatus, "Global group has been successfully added");
}

bool winsec::add_local_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* comment)
{
    std::unique_ptr<LOCALGROUP_INFO_1> lgi1 = std::make_unique<LOCALGROUP_INFO_1>();
    lgi1->lgrpi1_name = (LPWSTR)group_name;
    lgi1->lgrpi1_comment = (LPWSTR)comment;
    
    DWORD dwError = 0;
    NET_API_STATUS nStatus = NetLocalGroupAdd((LPCWSTR)server_name, 1, (LPBYTE)lgi1.get(), &dwError);
    return print_result(nStatus, "Local group has been successfully added");
}

bool winsec::change_local_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* comment)
{
    std::unique_ptr<LOCALGROUP_INFO_1> lgi1 = std::make_unique<LOCALGROUP_INFO_1>();
    lgi1->lgrpi1_name = (LPWSTR)group_name;
    lgi1->lgrpi1_comment = (LPWSTR)comment;

    DWORD dwError = 0;
    NET_API_STATUS nStatus = NetLocalGroupSetInfo((LPCWSTR)server_name, group_name,1, (LPBYTE)lgi1.get(), &dwError);
    return print_result(nStatus, "Local group's options have been successfully changed");
}

bool winsec::change_global_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* comment)
{
    std::unique_ptr<GROUP_INFO_1> lgi1 = std::make_unique<GROUP_INFO_1>();
    lgi1->grpi1_name = (LPWSTR)group_name;
    lgi1->grpi1_comment = (LPWSTR)comment;

    DWORD dwError = 0;
    NET_API_STATUS nStatus = NetGroupSetInfo((LPCWSTR)server_name, group_name, 1, (LPBYTE)lgi1.get(), &dwError);
    return print_result(nStatus, "Global group's options have been successfully changed");
}

bool winsec::del_global_group(const wchar_t* server_name, const wchar_t* group_name)
{
    NET_API_STATUS nStatus = NetGroupDel(server_name, group_name);
    return print_result(nStatus, "Global group has been successfully deleted");
}

bool winsec::del_local_group(const wchar_t* server_name, const wchar_t* group_name)
{
    NET_API_STATUS nStatus = NetLocalGroupDel(server_name, group_name);
    return print_result(nStatus, "Local group has been successfully deleted");
}

void winsec::get_all_user_info(const wchar_t* server_name, DWORD filter)
{
    USER_INFO_3* ui3;
    DWORD users_amount, totalentries, resume_handle = 0;
    NET_API_STATUS nStatus = NetUserEnum(server_name, 3, filter, (LPBYTE*)&ui3, MAX_PREFERRED_LENGTH, &users_amount,
        &totalentries, &resume_handle);
    print_result(nStatus, "");
    for (int i = 0; i < users_amount; ++i) {
        get_and_print(server_name, ui3[i].usri3_name,1);
    }
    nStatus = NetApiBufferFree(ui3);
}

void winsec::get_all_global_groups_info(const wchar_t* server_name)
{
    GROUP_INFO_3* gi3;
    DWORD groups_amount, totalentries;
    NET_API_STATUS nStatus = NetGroupEnum(server_name, 2, (LPBYTE*)&gi3,MAX_PREFERRED_LENGTH, &groups_amount,
        &totalentries, NULL);
    print_result(nStatus, "");
    for (int i = 0; i < groups_amount; ++i) {
        get_and_print(server_name, gi3[i].grpi3_name,0);
    }
    nStatus = NetApiBufferFree(gi3);
}

std::vector<char> winsec::get_sid_by_name(const wchar_t* server_name, const wchar_t* system_name)
{
    std::vector<TCHAR> domain_name(30);
    std::vector<char>sid_buffer(30);
    DWORD domain_name_size = 0, sid_size = 0;
    SID_NAME_USE eSidType;
    SID* sid = (SID*)sid_buffer.data();
    if (!LookupAccountNameW(server_name, system_name, sid_buffer.data(), &sid_size, domain_name.data(),
        &domain_name_size, &eSidType)) {
        sid_buffer.resize(sid_size);
        domain_name.resize(domain_name_size);
        sid = (SID*)sid_buffer.data();
        if (!LookupAccountNameW(server_name, system_name, sid_buffer.data(), &sid_size, domain_name.data(),
            &domain_name_size, &eSidType)) {
            print_result(GetLastError(), "");
            sid_buffer.clear();
            return sid_buffer;
        }
    }
    return sid_buffer;
}

std::wstring winsec::sid_to_wstring(SID* sid)
{
    LPTSTR sidstring;
    if (!ConvertSidToStringSid(sid, &sidstring)) {
        print_result(GetLastError(), "");
        return L"";
    }
    return sidstring;
}

LSA_HANDLE winsec::open_policy(const wchar_t* server_name, LSA_HANDLE& hPolicy)
{
    LSA_OBJECT_ATTRIBUTES ObjAttr;
    NTSTATUS Status;
    memset(&ObjAttr, 0, sizeof(ObjAttr));
    Status = LsaOpenPolicy((PLSA_UNICODE_STRING)server_name, &ObjAttr, POLICY_ALL_ACCESS,
        &hPolicy);
    if (!LSA_SUCCESS(Status))
        return INVALID_HANDLE_VALUE;
}

std::map<unsigned char,std::wstring> winsec::get_privilegies(const wchar_t* server_name, SID* sid)
{
    std::map<unsigned char, std::wstring> result = {};
    //std::wstring result = L"";
    LSA_HANDLE hPolicy;
    PLSA_UNICODE_STRING priv;
    ULONG priv_count;
    
    open_policy(server_name, hPolicy);
    if (hPolicy == INVALID_HANDLE_VALUE)
        return result;

    NTSTATUS Status = LsaEnumerateAccountRights(hPolicy, sid, &priv, &priv_count);
    if (Status == ERROR_SUCCESS){
        for (int k = 0; k < priv_count; k++){
            result.insert({ k+1, std::wstring(priv->Buffer) });
            priv++;
        }
    }
    else
        print_result(LsaNtStatusToWinError(Status), "");
    LsaClose(hPolicy);
    LsaFreeMemory(&priv);
    return result;
}

void winsec::get_all_local_groups_info(const wchar_t* server_name)
{
    LOCALGROUP_INFO_1* gi3;
    DWORD groups_amount, totalentries;
    NET_API_STATUS nStatus = NetLocalGroupEnum(server_name, 1, (LPBYTE*)&gi3, MAX_PREFERRED_LENGTH, &groups_amount,
        &totalentries, NULL);
    print_result(nStatus, "");
    for (int i = 0; i < groups_amount; ++i) {
        get_and_print(server_name, gi3[i].lgrpi1_name,0);
    }
    nStatus = NetApiBufferFree(gi3);
}

std::vector<std::wstring> winsec::get_user_ggroups(const wchar_t* server_name, const wchar_t* system_name)
{
    std::vector<std::wstring> result;
    DWORD entries, total_entries;
    GROUP_USERS_INFO_0* ggroups;
    NET_API_STATUS nStatus = NetUserGetGroups(server_name, system_name, 0, (LPBYTE*) & ggroups, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    print_result(nStatus, "");
    for (int i = 0; i < entries; i++)
        result.push_back(ggroups[i].grui0_name);
    NetApiBufferFree(ggroups);
    return result;
}

std::vector<std::wstring> winsec::get_user_lgroups(const wchar_t* server_name, const wchar_t* system_name)
{
    std::vector<std::wstring> result;
    LOCALGROUP_USERS_INFO_0* lgroups;
    DWORD entries, total_entries;
    NET_API_STATUS nStatus = NetUserGetLocalGroups(server_name, system_name, 0, LG_INCLUDE_INDIRECT, (LPBYTE*)&lgroups, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    print_result(nStatus, "");
    for (int i = 0; i < entries; i++)
        result.push_back(lgroups[i].lgrui0_name);
    nStatus = NetApiBufferFree(lgroups);
    return result;
}

std::vector<std::wstring> winsec::get_lgroup_members(const wchar_t* server_name, const wchar_t* system_name)
{
    std::vector<std::wstring> result;
    DWORD entries, total_entries;
    LOCALGROUP_MEMBERS_INFO_3* members;
    NET_API_STATUS nStatus = NetLocalGroupGetMembers(server_name, system_name, 3, (LPBYTE*) & members, MAX_PREFERRED_LENGTH, &entries, &total_entries, NULL);
    print_result(nStatus, "");
    for (int i = 0; i < entries; i++)
        result.push_back(members[i].lgrmi3_domainandname);
    NetApiBufferFree(members);
    return result;
}

void winsec::get_and_print(const wchar_t* server_name, const wchar_t* system_name, bool is_user)
{
    std::vector<char> t = get_sid_by_name(server_name, system_name);
    SID* sid = (SID*)t.data();
    std::wstring sid_str = sid_to_wstring(sid);
    std::cout << std::string(sid_str.size(), '_') << std::endl;
    std::wcout << "Name: "<<system_name << L"\nSID: " << sid_str << std::endl;
    if (is_user) {
        std::wcout << "Local Groups:" << std::endl;
        std::vector<std::wstring> lgroups = get_user_lgroups(server_name, system_name);
        for (const auto& elem : lgroups)
            std::wcout << L"\t" << elem << std::endl;
        if (lgroups.empty())
            std::wcout << L"\t None" << std::endl;
        std::wcout << "Global Groups:" << std::endl;
        std::vector<std::wstring> ggroups = get_user_ggroups(server_name, system_name);
        for (const auto& elem : ggroups)
            std::wcout << L"\t" << elem << std::endl;
        if (ggroups.empty())
            std::wcout << L"\t None" << std::endl;
    }
    else {
        std::wcout << "Members:" << std::endl;
        std::vector<std::wstring> members = get_lgroup_members(server_name, system_name);
        for (const auto& elem : members)
            std::wcout << L"\t" << elem << std::endl;
        if (members.empty())
            std::wcout << L"\t None" << std::endl;
    }
    std::cout << "Privileges: " << std::endl;
    std::map<unsigned char,std::wstring> priv = get_privilegies(server_name, sid);
    for (const auto& elem : priv)
        std::wcout << "\t" << elem.first << ": " << elem.second << std::endl;
    
}

LSA_UNICODE_STRING winsec::wstring_to_lsa_unicode_string(const std::wstring& str)
{
    LSA_UNICODE_STRING lsaWStr;
    DWORD len = 0;
    len = str.length();
    LPWSTR cstr = new WCHAR[len + 1];
    memcpy(cstr, str.c_str(), (len + 1) * sizeof(WCHAR));
    lsaWStr.Buffer = cstr;
    lsaWStr.Length = (USHORT)((len) * sizeof(WCHAR));
    lsaWStr.MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
    return lsaWStr;
}

void winsec::add_privileges(const wchar_t* server_name,const wchar_t* system_name)
{
    std::vector<char> t = get_sid_by_name(server_name, system_name);
    SID* sid = (SID*)t.data();
    std::cout << "Enter the numbers of the privileges to be added, separating them with spaces" << std::endl;
    for (const auto& elem : privegies)
        std::wcout << elem.first << ": " << elem.second << std::endl;
    std::string input_str;
    std::getline(std::cin, input_str);
    std::stringstream iss(input_str);
    int number;
    std::vector<int> numbers;
    while (iss >> number)
        numbers.push_back(number);
    NTSTATUS nStatus;
    LSA_HANDLE hPolicy;
    open_policy(server_name, hPolicy);
    for (const auto& elem : numbers) {
        LSA_UNICODE_STRING PrivilegeString = wstring_to_lsa_unicode_string(privegies[elem]);
        nStatus = LsaAddAccountRights(hPolicy, sid, &PrivilegeString,1);
        print_result(LsaNtStatusToWinError(nStatus), "Privilege has been successfuly added");
    }
    LsaClose(hPolicy);
}

void winsec::del_privileges(const wchar_t* server_name, const wchar_t* system_name)
{
    std::vector<char> t = get_sid_by_name(server_name, system_name);
    SID* sid = (SID*)t.data();
    std::wcout << "Current privileges: " << std::endl;
    std::map<unsigned char, std::wstring> priv = get_privilegies(server_name, sid);
    for (const auto& elem : priv)
        std::wcout << "\t" << elem.first << ": " << elem.second << std::endl;
    std::cout << "Enter the numbers of the privileges to be deleted, separating them with spaces" << std::endl;
    std::string input_str;
    std::getline(std::cin, input_str);
    std::stringstream iss(input_str);
    int number;
    std::vector<int> numbers;
    while (iss >> number)
        numbers.push_back(number);
    LSA_HANDLE hPolicy;
    open_policy(server_name, hPolicy);
    NTSTATUS nStatus;
    for (const auto& elem : numbers) {
        LSA_UNICODE_STRING PrivilegeString = wstring_to_lsa_unicode_string(priv[elem]);
        nStatus = LsaRemoveAccountRights(hPolicy, sid, false,&PrivilegeString, 1);
        print_result(LsaNtStatusToWinError(nStatus), "Privilege has been successfuly deleted");
    }
    LsaClose(hPolicy);
}

void winsec::add_user_to_local_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* system_name) 
{
    std::vector<char> t = get_sid_by_name(server_name, system_name);
    SID* sid = (SID*)t.data();
    LPLOCALGROUP_MEMBERS_INFO_3 pBuf = new LOCALGROUP_MEMBERS_INFO_3;
    pBuf->lgrmi3_domainandname = (LPWSTR)system_name;
    NET_API_STATUS nStatus = NetLocalGroupAddMembers(server_name, group_name, 3,(LPBYTE)pBuf,1);
    print_result(nStatus, "User has been successfully added to local group");
}

void winsec::del_user_from_local_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* system_name) {
    std::vector<char> t = get_sid_by_name(server_name, system_name);
    SID* sid = (SID*)t.data();
    NET_API_STATUS nStatus = NetLocalGroupDelMember(server_name, group_name, sid);
    print_result(nStatus, "User has been successfully deleted to local group");
}
