#include "parser.h"

parser::parser(int ac,wchar_t* av[], std::shared_ptr<winsec>bs) {
    argc = ac;
    argv = av;
    base = bs;
}
const wchar_t* parser::is_null(const std::wstring& str)
{
    if (str.empty())
        return nullptr;
    else
        return str.data();
}
void parser::user_info(const po::variables_map& vm)
{
    std::wstring server_name;
    int filter = 0;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("filter"))
        filter = vm["filter"].as<int>();
    base->get_all_user_info(is_null(server_name), filter);
}

void parser::lgroup_info(const po::variables_map& vm)
{   
    std::wstring server_name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    base->get_all_local_groups_info(is_null(server_name));
}

void parser::ggroup_info(const po::variables_map& vm)
{
    std::wstring server_name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    base->get_all_global_groups_info(is_null(server_name));
}

void parser::add_user(const po::variables_map& vm)
{
    std::wstring server_name,user_name,password,dir,comment;
    int int_priv = 1;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        user_name = vm["name"].as<std::wstring>();
    if (vm.count("password"))
        password = vm["password"].as<std::wstring>();
    if (vm.count("priv"))
        int_priv = vm["priv"].as<int>();
    if (vm.count("dir"))
        dir = vm["dir"].as<std::wstring>();
    if (vm.count("comment"))
        comment = vm["comment"].as<std::wstring>();
    base->add_user(is_null(server_name), is_null(user_name), is_null(password), int_priv, is_null(dir), is_null(comment),0,NULL);
}

void parser::add_lgroup(const po::variables_map& vm)
{
    std::wstring server_name, group_name, comment;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        group_name = vm["name"].as<std::wstring>();
    if (vm.count("comment"))
        comment = vm["comment"].as<std::wstring>();
    base->add_local_group(is_null(server_name), is_null(group_name),is_null(comment));
}

void parser::add_ggroup(const po::variables_map& vm)
{
    std::wstring server_name, group_name, comment;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        group_name = vm["name"].as<std::wstring>();
    if (vm.count("comment"))
        comment = vm["comment"].as<std::wstring>();
    base->add_global_group(is_null(server_name), is_null(group_name), is_null(comment));
}

void parser::add_priv(const po::variables_map& vm)
{
    std::wstring server_name, group_name, comment;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        group_name = vm["name"].as<std::wstring>();
    base->add_privileges(is_null(server_name), is_null(group_name));
}

void parser::add_usertogroup(const po::variables_map& vm)
{
    std::wstring server_name, group_name, name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("groupname"))
        group_name = vm["groupname"].as<std::wstring>();
    if (vm.count("name"))
        name = vm["name"].as<std::wstring>();
    base->add_user_to_local_group(is_null(server_name), is_null(group_name), is_null(name));
}

void parser::del_user(const po::variables_map& vm)
{
    std::wstring server_name, name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        name = vm["name"].as<std::wstring>();
    base->del_user(is_null(server_name), is_null(name));
}

void parser::del_lgroup(const po::variables_map& vm)
{
    std::wstring server_name, name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        name = vm["name"].as<std::wstring>();
    base->del_local_group(is_null(server_name), is_null(name));
}

void parser::del_ggroup(const po::variables_map& vm)
{
    std::wstring server_name, name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        name = vm["name"].as<std::wstring>();
    base->del_global_group(is_null(server_name), is_null(name));
}

void parser::del_priv(const po::variables_map& vm)
{
    std::wstring server_name, name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        name = vm["name"].as<std::wstring>();
    base->del_privileges(is_null(server_name), is_null(name));
}

void parser::del_userfromgroup(const po::variables_map& vm)
{
    std::wstring server_name, group_name, name;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("groupname"))
        group_name = vm["groupname"].as<std::wstring>();
    if (vm.count("name"))
        name = vm["name"].as<std::wstring>();
    base->del_user_from_local_group(is_null(server_name), is_null(group_name), is_null(name));
}

void parser::change_user(const po::variables_map& vm)
{
    std::wstring server_name, user_name, password, dir, comment;
    int int_priv = 1;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        user_name = vm["name"].as<std::wstring>();
    if (vm.count("password"))
        password = vm["password"].as<std::wstring>();
    if (vm.count("priv"))
        int_priv = vm["priv"].as<int>();
    if (vm.count("dir"))
        dir = vm["dir"].as<std::wstring>();
    if (vm.count("comment"))
        comment = vm["comment"].as<std::wstring>();
    base->change_user(is_null(server_name), is_null(user_name), is_null(password), int_priv, is_null(dir), is_null(comment), 0, NULL);
}

void parser::change_lgroup(const po::variables_map& vm)
{
    std::wstring server_name, group_name, comment;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        group_name = vm["name"].as<std::wstring>();
    if (vm.count("comment"))
        comment = vm["comment"].as<std::wstring>();
    base->change_local_group(is_null(server_name), is_null(group_name), is_null(comment));
}

void parser::change_ggroup(const po::variables_map& vm)
{
    std::wstring server_name, group_name, comment;
    if (vm.count("servername"))
        server_name = vm["servername"].as<std::wstring>();
    if (vm.count("name"))
        group_name = vm["name"].as<std::wstring>();
    if (vm.count("comment"))
        comment = vm["comment"].as<std::wstring>();
    base->change_global_group(is_null(server_name), is_null(group_name), is_null(comment));
}

void parser::main_parse() {
    po::options_description desc("General options");
    std::wstring show_task,add_task,del_task, change_task;
    desc.add_options()
        ("help,h", "Show help")
        ("show,s", po::wvalue<std::wstring>(&show_task), "Select task: user, lgroup, ggroup")
        ("add,a",po::wvalue<std::wstring>(&add_task),"Select task: user, lgroup, ggroup, priv, usertogroup")
        ("del,d", po::wvalue<std::wstring>(&del_task), "Select task: user, lgroup, ggroup, priv, userfromgroup")
        ("change,q", po::wvalue<std::wstring>(&change_task), "Select task: user, lgroup, ggroup");
    
    po::options_description show_user_desc("Show user options");
    show_user_desc.add_options()
        ("servername,n", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("filter,f", po::value<int>()->default_value(0), "Filter 1,2,3 nothing for all");
    
    po::options_description show_lgroup_desc("Show lgroup options");
    show_lgroup_desc.add_options()
        ("servername,n", po::wvalue<std::wstring>(), "Server name or nothing for local");

    po::options_description show_ggroup_desc("Show ggroup options");
    show_ggroup_desc.add_options()
        ("servername,n", po::wvalue<std::wstring>(), "Server name or nothing for local");
    
    po::options_description add_user_desc("Add user options");
    add_user_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "User name")
        ("password,p", po::wvalue<std::wstring>(), "User password")
        ("priv,k", po::value<int>(), "User privilege: 0(USER_PRIV_GUEST), 1(USER_PRIV_USER), 2(USER_PRIV_ADMIN)")
        ("dir,d", po::wvalue<std::wstring>(), "User home dir")
        ("comment,c", po::wvalue<std::wstring>(), "Comment");
    
    po::options_description add_lgroup_desc("Add lgroup options");
    add_lgroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Lgroup name")
        ("comment,c", po::wvalue<std::wstring>(), "Comment");

    po::options_description add_ggroup_desc("Add ggroup options");
    add_ggroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Ggroup name")
        ("comment,c", po::wvalue<std::wstring>(), "Comment");
    
    po::options_description add_priv_desc("Add privilege options");
    add_priv_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Lgroup name");

    po::options_description add_usertogroup_desc("Add usertogroup options");
    add_usertogroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("groupname,g", po::wvalue<std::wstring>(), "Lgroup name")
        ("name,n", po::wvalue<std::wstring>(), "User name");


    po::options_description del_user_desc("Del user options");
    del_user_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "User name");

    po::options_description del_lgroup_desc("Del lgroup options");
    del_lgroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Lgroup name");

    po::options_description del_ggroup_desc("Del lgroup options");
    del_ggroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Ggroup name");

    po::options_description del_priv_desc("Del privilege options");
    del_priv_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Name");

    po::options_description del_userfromgroup_desc("Del userfromgroup options");
    del_userfromgroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("groupname,g", po::wvalue<std::wstring>(), "Lgroup name")
        ("name,n", po::wvalue<std::wstring>(), "User name");

    po::options_description change_user_desc("Change user options");
    change_user_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "User name")
        ("password,p", po::wvalue<std::wstring>(), "User password")
        ("priv,k", po::value<int>(), "User privilege: 0(USER_PRIV_GUEST), 1(USER_PRIV_USER), 2(USER_PRIV_ADMIN)")
        ("dir,d", po::wvalue<std::wstring>(), "User home dir")
        ("comment,c", po::wvalue<std::wstring>(), "Comment");

    po::options_description change_lgroup_desc("Change lgroup options");
    change_lgroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Lgroup name")
        ("comment,c", po::wvalue<std::wstring>(), "Comment");

    po::options_description change_ggroup_desc("Change ggroup options");
    change_ggroup_desc.add_options()
        ("servername,i", po::wvalue<std::wstring>(), "Name of server or nothing for local")
        ("name,n", po::wvalue<std::wstring>(), "Ggroup name")
        ("comment,c", po::wvalue<std::wstring>(), "Comment");

    po::variables_map vm;
    try {
        po::wparsed_options parsed = po::wcommand_line_parser(argc, argv).options(desc).allow_unregistered().run();
        po::store(parsed, vm);
        po::notify(vm);
        if (show_task == L"user") {
            desc.add(show_user_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            user_info(vm);
        }
        else if (show_task == L"lgroup") {
            desc.add(show_lgroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            lgroup_info(vm);
        }
        else if (show_task == L"ggroup") {
            desc.add(show_ggroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            ggroup_info(vm);
        }
        else if (add_task == L"user") {
            desc.add(add_user_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            add_user(vm);
        }
        else if (add_task == L"lgroup") {
            desc.add(add_lgroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            add_lgroup(vm);
        }
        else if (add_task == L"ggroup") {
            desc.add(add_ggroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            add_ggroup(vm);
        }
        else if (add_task == L"priv") {
            desc.add(add_lgroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            add_priv(vm);
        }
        else if (add_task == L"usertogroup") {
            desc.add(add_usertogroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            add_usertogroup(vm);
        }
        else if (del_task == L"user") {
            desc.add(del_user_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            del_user(vm);
        }
        else if (del_task == L"lgroup") {
            desc.add(del_lgroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            del_lgroup(vm);
        }
        else if (del_task == L"ggroup") {
            desc.add(del_ggroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            del_ggroup(vm);
        }
        else if (del_task == L"priv") {
            desc.add(del_priv_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            del_priv(vm);
        }
        else if (del_task == L"userfromgroup") {
            desc.add(del_userfromgroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            del_userfromgroup(vm);
        }
        else if (change_task == L"user") {
            desc.add(change_user_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            change_user(vm);
        }
        else if (change_task == L"lgroup") {
            desc.add(change_lgroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            change_lgroup(vm);
        }
        else if (change_task == L"ggroup") {
            desc.add(change_ggroup_desc);
            po::store(po::parse_command_line(argc, argv, desc), vm);
            change_ggroup(vm);
        }
        else {
            desc.add(show_user_desc).add(show_lgroup_desc).add(show_ggroup_desc).add(add_user_desc).add(add_lgroup_desc).add(add_ggroup_desc);
            desc.add(add_priv_desc).add(add_usertogroup_desc).add(del_user_desc).add(del_lgroup_desc).add(del_ggroup_desc).add(del_priv_desc).add(del_userfromgroup_desc);
            desc.add(change_user_desc).add(change_lgroup_desc).add(change_ggroup_desc);
            std::cout << desc << std::endl;
        }
    }
    catch (std::exception& ex) {
        std::cout << desc << std::endl;
    }
}