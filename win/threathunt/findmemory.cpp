// findmemory.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

char* GetAddressOfData(DWORD pid, const char *data, size_t len)
{
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        
        MEMORY_BASIC_INFORMATION info;
        std::vector<char> chunk;
        char* p = 0;
        while (p < si.lpMaximumApplicationAddress)
        {
            if (VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
            {
                p = (char*)info.BaseAddress;
                chunk.resize(info.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(process, p, &chunk[0], info.RegionSize, &bytesRead))
                {
                    for (size_t i = 0; i < (bytesRead - len); ++i)
                    {
                        if (memcmp(data, &chunk[i], len) == 0)
                        {
                            return (char*)p + i;
                        }
                    }
                }
                p += info.RegionSize;
            }
        }
    }
    return 0;
}

void help()
{
    std::cout << "findmemory.exe pid string_to_find "<<std::endl;
    std::cout << "Example:\r\n findmemory.exe 6666  miriai " << std::endl;
}

int main(int argc,char* argv[])
{
    if (argc < 2)
    {
        help();
        return 0;
    }
    else {
        char *someData = argv[2];
        
        //Pass whatever process id you like here instead.
        DWORD pid = std::stoi(argv[1]);
        char* ret = GetAddressOfData(pid, someData, sizeof(someData));
        if (ret)
        {
            std::cout << "Found! Position: " << (void*)ret << "\n";
        }
        else
        {
            std::cout << "Not found\n";
        }
    }
    
    
    return 0;
}
