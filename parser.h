#pragma once
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include "winsec.h"
namespace po = boost::program_options;
class parser
{
private:
	
	int argc;
	wchar_t** argv;
	std::shared_ptr<winsec>base;
	void user_info(const po::variables_map& vm);
	void lgroup_info(const po::variables_map& vm);
	void add_user(const po::variables_map& vm);
	void add_lgroup(const po::variables_map& vm);
	void add_priv(const po::variables_map& vm);
	void add_usertogroup(const po::variables_map& vm);
	void del_user(const po::variables_map& vm);
	void del_lgroup(const po::variables_map& vm);
	void del_priv(const po::variables_map& vm);
	void del_userfromgroup(const po::variables_map& vm);
	void change_user(const po::variables_map& vm);
	void change_lgroup(const po::variables_map& vm);
	void ggroup_info(const po::variables_map& vm);
	void add_ggroup(const po::variables_map& vm);
	void del_ggroup(const po::variables_map& vm);
	void change_ggroup(const po::variables_map& vm);
public:
	const wchar_t* is_null(const std::wstring&);
	parser(int argc, wchar_t* argv[], std::shared_ptr<winsec>bs);
	void main_parse();
};

