// injectorApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

#include <string>
#include <cstring>

#include <easyhook.h>
#include <TlHelp32.h>
#include <vector>

int main()
{
    std::cout << "Hello World!\n"; 

	DWORD processId = 0;
	std::vector<DWORD> pids;
	//std::wcout << "Enter the target process Id: ";
	//std::cin >> processId;

	std::wstring target = L"Ledger Live.exe";

	std::wcout << "target process name: " << target << std::endl;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (std::wstring(entry.szExeFile) == target)
			{
				//processId = entry.th32ProcessID;
				pids.emplace_back(entry.th32ProcessID);
			}
		}
	}

	CloseHandle(snapshot);

	for (int i(0); i < pids.size(); ++i) {
		std::wcout << "target process id: " << pids[i] << std::endl;

		//DWORD freqOffset = 0;
		//std::cout << "Enter a frequency offset in hertz (e.g. 800): ";
		//std::cin >> freqOffset;

		// WCHAR* dllToInject = L"..\\Debug\\hookDLL.dll";
		WCHAR dllToInject[] = L"C:\\Users\\Hossein\\Desktop\\myHack\\x64\\Debug\\hookDLL.dll";
		// WCHAR dllToInject[] = L"C:\\Users\\Hossein\\Desktop\\myHack\\Debug\\hookDLL.dll";
		wprintf(L"Attempting to inject: %s\n\n", dllToInject);

		// Inject dllToInject into the target process Id, passing 
		// freqOffset as the pass through data.
		NTSTATUS nt = RhInjectLibrary(
			pids[i],   // The process to inject into
			0,           // ThreadId to wake up upon injection
			EASYHOOK_INJECT_DEFAULT,
			NULL, // 32-bit
			dllToInject,		 // 64-bit not provided
			NULL, // data to send to injected DLL entry point
			0// size of data to send
		);

		if (nt != 0)
		{
			printf("RhInjectLibrary failed with error code = %d\n", nt);
			PWCHAR err = RtlGetLastErrorString();
			std::wcout << err << "\n";
		}
		else
		{
			std::wcout << L"Library injected successfully.\n";
		}
	}

	//std::wcout << "Press Enter to exit";
	//std::wstring input;
	//std::getline(std::wcin, input);
	//std::getline(std::wcin, input);
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
