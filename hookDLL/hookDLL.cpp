// hookDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

#include <easyhook.h>
#include <string>
#include <iostream>
#include <Windows.h>
#include <WinNT.h>
#include <hidsdi.h>
#include <fstream>
#include <hidclass.h>
#include <winioctl.h>
#include <vector>

std::string byte_2_hexstr(char* bytes, int size) {
	char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',   'B','C','D','E','F' };
	std::string str;
	for (int i = 0; i < size; ++i) {
		const char ch = bytes[i];
		str.append(&hex[(ch & 0xF0) >> 4], 1);
		str.append(&hex[ch & 0xF], 1);
	}
	return str;
}

HANDLE hidHandle = 0;
bool hasConsole = false;
std::ofstream fs;

HANDLE CreateFileAHook(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	std::string temp(lpFileName, 11);
	//if (temp.compare("\\\\.\\USB#ROOT") == 0)
	if (temp.compare("\\\\?\\hid#vid") != 0)
	{
		return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}

	if (hasConsole == false) {
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		std::cout << "Injected process Id: " << GetCurrentProcessId() << std::endl;
		std::cout << "HID path: " << lpFileName << std::endl;
		fs.open("C:\\Users\\Hossein\\Desktop\\log\\" + std::to_string(GetCurrentProcessId()) + ".txt");
		fs << "Injected process Id: " << GetCurrentProcessId() << std::endl;
		fs << "HID path: " << lpFileName << std::endl;
		hasConsole = true;
	}

	HANDLE handle = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);

	//std::cout << "\nCreateFileA!\n" << handle << std::endl;
	//fs << "\nCreateFileA!\n" << handle << std::endl;
	
	hidHandle = handle;

	return handle;
}

/*BOOLEAN HidD_GetAttributesHook(
	HANDLE           HidDeviceObject,
	PHIDD_ATTRIBUTES Attributes)
{
	if (hasConsole == false) {
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		fs.open("C:\\Users\\Hossein\\Desktop\\log.txt");
		std::cout << "Injected process Id: " << GetCurrentProcessId() << "\n";
		fs << "Injected process Id: " << GetCurrentProcessId() << "\n";
		hasConsole = true;
	}

	std::cout << "\nHidD_GetAttributesHook!\n" << HidDeviceObject << std::endl;
	fs << "\nHidD_GetAttributesHook!\n" << HidDeviceObject << std::endl;

	hidHandle = HidDeviceObject;

	return HidD_GetAttributes(HidDeviceObject,Attributes);
}*/

/*BOOL DeviceIoControlHook(
	HANDLE       hDevice,
	DWORD        dwIoControlCode,
	LPVOID       lpInBuffer,
	DWORD        nInBufferSize,
	LPVOID       lpOutBuffer,
	DWORD        nOutBufferSize,
	LPDWORD      lpBytesReturned,
	LPOVERLAPPED lpOverlapped
)
{
	if (dwIoControlCode == IOCTL_HID_GET_FEATURE)
	{
		if (hasConsole == false) {
			AllocConsole();
			freopen("CONOUT$", "w", stdout);
			fs.open("C:\\Users\\Hossein\\Desktop\\log.txt");
			std::cout << "Injected process Id: " << GetCurrentProcessId() << "\n";
			fs << "Injected process Id: " << GetCurrentProcessId() << "\n";
			hasConsole = true;
		}

		std::cout << "\nDeviceIoControl\n" << hDevice << std::endl;
		fs << "\nDeviceIoControl\n" << hDevice << std::endl;

		hidHandle = hDevice;
	}

	return DeviceIoControl(hDevice,dwIoControlCode,lpInBuffer,nInBufferSize,lpOutBuffer,nOutBufferSize,lpBytesReturned,lpOverlapped);
}*/

BOOL WINAPI WriteFileHook(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
{
	if (hFile == hidHandle) {
		std::cout << "\nWriteFile!\n" << hFile << std::endl << nNumberOfBytesToWrite << std::endl;
		fs << "\nWriteFile!\n" << hFile << std::endl << nNumberOfBytesToWrite << std::endl;
		char *s = (char*)lpBuffer;
		std::string ss = byte_2_hexstr(s, nNumberOfBytesToWrite);
		std::cout << "Hex: " << ss << std::endl;
		fs << "Hex: " << ss << std::endl;
		std::cout << "Asc: " << s << std::endl;
		fs << "Asc: " << s << std::endl;

		

		//if (s[8] == 0xe0)
		/*{
			std::cout << "Hello: " << std::hex << s[8] << std::endl;
			std::cout << "Hello: " << std::hex << (char)0xe0 << std::endl;
		}*/

		if ((s[8] == (char)0xe0) &&
			(s[9] == (char)0x44) &&
			(s[10] == (char)0x80) &&
			(s[11] == (char)0x02) &&
			(s[13] == (char)0x02))
		{
			std::cout << "Fund (before confirm): " << ss.substr(50 * 2, 16) << std::endl;
			//std::cout << std::hex << s[50] << std::endl;
			s[50] = (char)0xb6;
		}

		if ((s[8] == (char)0xe0) &&
			(s[9] == (char)0x44) &&
			(s[10] == (char)0x80) &&
			(s[11] == (char)0x80) &&
			(s[13] == (char)0x02))
		{
			std::cout << "Fund (after confirm): " << ss.substr(50 * 2, 16) << std::endl;
			s[50] = (char)0xb6;
		}

		if ((s[8] == (char)0xe0) &&
			(s[9] == (char)0x4a) &&
			(s[10] == (char)0x00) &&
			(s[11] == (char)0x00) &&
			(s[13] == (char)0x02))
		{
			std::cout << "Change: " << ss.substr(48 * 2, 16) << std::endl;
		}

		lpBuffer = (void*)s;
	}

	return WriteFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToWrite,
		lpNumberOfBytesWritten,
		lpOverlapped
	);
}

/*BOOL WINAPI ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped)
{
	BOOL result = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);

	if (hFile == hidHandle) {
		std::cout << "\nReadFile!\n" << hFile << std::endl << *lpNumberOfBytesRead << std::endl;
		fs << "\nReadFile!\n" << hFile << std::endl << *lpNumberOfBytesRead << std::endl;
		char *s = (char*)lpBuffer;
		std::string ss = byte_2_hexstr(s, *lpNumberOfBytesRead);
		std::cout << "Hex: " << ss << std::endl;
		fs << "Hex: " << ss << std::endl;
		std::cout << "Asc: " << s << std::endl;
		fs << "Asc: " << s << std::endl;
	}

	return result;
}*/


// EasyHook will be looking for this export to support DLL injection. If not found then 
// DLL injection will fail.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	/*std::cout << "\n\nNativeInjectionEntryPointt(REMOTE_ENTRY_INFO* inRemoteInfo)\n\n" <<
		"IIIII           jjj               tt                dd !!! \n"
		" III  nn nnn          eee    cccc tt      eee       dd !!! \n"
		" III  nnn  nn   jjj ee   e cc     tttt  ee   e  dddddd !!! \n"
		" III  nn   nn   jjj eeeee  cc     tt    eeeee  dd   dd     \n"
		"IIIII nn   nn   jjj  eeeee  ccccc  tttt  eeeee  dddddd !!! \n"
		"              jjjj                                         \n\n";*/

	//std::cout << "Injected by process Id: " << inRemoteInfo->HostPID << "\n";
	//std::cout << "Injected process Id: " << GetCurrentProcessId() << "\n";

	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

	//std::cout << "\n";
	//std::cout << "Win32 HidD_GetAttributes found at address: " << GetProcAddress(GetModuleHandle(TEXT("Hid")), "HidD_GetAttributes") << "\n";
	//std::cout << "Win32 WriteFile found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile") << "\n";

	// Install the hook
	NTSTATUS result = LhInstallHook(
		//GetProcAddress(GetModuleHandle(TEXT("Hid")), "HidD_GetAttributes"),
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileA"),
		//HidD_GetAttributesHook,
		CreateFileAHook,
		NULL,
		&hHook);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		std::wcout << "Failed to install hook: ";
		std::wcout << s;
	}
	else
	{
		std::cout << "Hook installed successfully.";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
	}


	HOOK_TRACE_INFO hHook2 = { NULL }; // keep track of our hook

	// Install the hook
	result = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile"),
		WriteFileHook,
		NULL,
		&hHook2);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		std::wcout << "Failed to install hook: ";
		std::wcout << s;
	}
	else
	{
		std::cout << "Hook installed successfully.";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook2);
	}


	/*HOOK_TRACE_INFO hHook3 = { NULL }; // keep track of our hook

	// Install the hook
	result = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFile"),
		ReadFileHook,
		NULL,
		&hHook3);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		std::wcout << "Failed to install hook: ";
		std::wcout << s;
	}
	else
	{
		std::cout << "Hook installed successfully.";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook3);
	}*/

	/*HOOK_TRACE_INFO hHook4 = { NULL }; // keep track of our hook

	// Install the hook
	result = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "DeviceIoControl"),
		DeviceIoControlHook,
		NULL,
		&hHook4);
	if (FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		std::wcout << "Failed to install hook: ";
		std::wcout << s;
	}
	else
	{
		std::cout << "Hook installed successfully.";
		ULONG ACLEntries[1] = { 0 };
		LhSetExclusiveACL(ACLEntries, 1, &hHook4);
	}*/


	return;
}

