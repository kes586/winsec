#include <memory>
#include <locale.h>
#include "parser.h"
#include "winsec.h"
#pragma comment(lib, "netapi32.lib")
int wmain(int argc, wchar_t* argv[]) {
    setlocale(LC_ALL, "");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
	std::shared_ptr<winsec>base = std::make_unique<winsec>();
    std::unique_ptr<parser>par = std::make_unique<parser>(argc,argv,base);
    par->main_parse();
    return 0;
}