#pragma once
#pragma comment(lib, "netapi32.lib")
#include <iostream>
#include <vector>
#include <windows.h> 
#include <lm.h>
#include <string>
#include <memory>
#include <sddl.h>
#include <ntsecapi.h>
#include <map>
#include <sstream>
class winsec
{
private:
	std::map<unsigned char,std::wstring> privegies;
	std::string get_error(DWORD error);
	bool print_result(NET_API_STATUS nStatus, std::string result_message);
	std::vector<char> get_sid_by_name(const wchar_t* server_name, const wchar_t* system_name);
	std::wstring sid_to_wstring(SID* sid);
	std::map<unsigned char, std::wstring> get_privilegies(const wchar_t* server_name, SID* sid);
	void get_and_print(const wchar_t* server_name, const wchar_t* system_name, bool is_user);
	LSA_HANDLE open_policy(const wchar_t* server_name, LSA_HANDLE& hPolicy);
	LSA_UNICODE_STRING wstring_to_lsa_unicode_string(const std::wstring& str);
	std::vector<std::wstring> get_user_ggroups(const wchar_t* server_name, const wchar_t* system_name);
	std::vector<std::wstring> get_user_lgroups(const wchar_t* server_name, const wchar_t* system_name);
	std::vector<std::wstring> get_lgroup_members(const wchar_t* server_name, const wchar_t* system_name);
public:
	winsec();
	bool add_user(const wchar_t* server_name, const wchar_t* user_name, const wchar_t* password,
		DWORD user_priv, const wchar_t* home_dir, const wchar_t* comment, DWORD flags,
		const wchar_t* script_path);
	bool change_user(const wchar_t* server_name, const wchar_t* user_name, const wchar_t* password,
		DWORD user_priv, const wchar_t* home_dir, const wchar_t* comment, DWORD flags,
		const wchar_t* script_path);
	bool del_user(const wchar_t* server_name, const wchar_t* user_name);
	bool add_global_group(const wchar_t* server_name, const wchar_t* group_name,const wchar_t* comment);
	bool add_local_group(const wchar_t* server_name, const wchar_t* group_name,const wchar_t* comment);
	bool change_local_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* comment);
	bool change_global_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* comment);
	bool del_local_group(const wchar_t* server_name, const wchar_t* group_name);
	bool del_global_group(const wchar_t* server_name, const wchar_t* group_name);
	void get_all_user_info(const wchar_t* server_name, DWORD filter);
	void get_all_global_groups_info(const wchar_t* server_name);
	void get_all_local_groups_info(const wchar_t* server_name);
	void add_privileges(const wchar_t* server_name, const wchar_t* system_name);
	void del_privileges(const wchar_t* server_name, const wchar_t* system_name);
	void add_user_to_local_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* system_name);
	void del_user_from_local_group(const wchar_t* server_name, const wchar_t* group_name, const wchar_t* system_name);
};

