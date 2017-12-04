#include <process.h>
#include <iostream>
#include <Windows.h>
#include "dbghelp.h"
#include <tchar.h>
using namespace std;

//from  https://stackoverflow.com/questions/22465253/symgetlinefromaddr-not-working-properly
// 添加对dbghelp.lib的编译依赖
//
#pragma comment(lib, "dbghelp.lib")

int LogStackTrace()
{
    void *stack[1024];
    HANDLE process = GetCurrentProcess();
    SymInitialize(process, NULL, TRUE);
    WORD numberOfFrames = CaptureStackBackTrace(0, 1000, stack, NULL);
    SYMBOL_INFO *symbol = (SYMBOL_INFO *)malloc(sizeof(SYMBOL_INFO));
    symbol->MaxNameLen = 1024;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    IMAGEHLP_LINE *line = (IMAGEHLP_LINE *)malloc(sizeof(IMAGEHLP_LINE));
    line->SizeOfStruct = sizeof(IMAGEHLP_LINE);
    printf("Caught exception ");
    for (int i = 0; i < numberOfFrames; i++)
    {
        SymFromAddr(process, (DWORD64)(stack[i]), NULL, symbol);
        //SymGetLineFromAddr(process, (DWORD)(stack[i]), NULL, line);
        DWORD dwDisplacement;
        SymGetLineFromAddr(process, (DWORD)(stack[i]), &dwDisplacement, line);
        printf("at %s in %s, address 0x%0X\n", symbol->Name, line->FileName, symbol->Address);
    }
    return 0;
}

void function2()
{
    int a = 0;
    int b = 0;
    throw new exception("Expected exception.");
}

void function1()
{
    int a = 0;
    function2();
}

void function0()
{
    function1();
}

static void threadFunction(void *param)
{
    try
    {
        function0();
    }
    catch (...)
    {
        LogStackTrace();
    }
}

int _tmain(int argc, _TCHAR* argv[])
{
    try
    {
        _beginthread(threadFunction, 0, NULL);
    }
    catch (...)
    {
        LogStackTrace();
    }
    printf("Press any key to exit.\n");
    cin.get();
    return 0;
}

