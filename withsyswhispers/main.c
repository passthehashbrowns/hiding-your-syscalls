#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE


#include <Windows.h>
#include <stdio.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include "Syscalls.h"

#pragma comment (lib, "Dbghelp.lib")

void createObfuscatedSyscall(LPVOID SyscallFunction, LPVOID ntdllSyscallFunction);
BOOL resetNtdllProtection(LPVOID ntdllPointer, DWORD protection);


PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
	return (PVOID)RVA;
}


LPVOID GetFirstStub(PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection)
{
	PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
	PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);
	for (int i = 0; i < exportDirectory->NumberOfNames; i++)
	{

		DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
		DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
		LPCSTR functionNameResolved = (LPCSTR)functionNameVA;

		if (functionNameResolved[0] == 'N' && functionNameResolved[1] == 't')
		{
			
			return (LPVOID)functionVA;
		}
	}
	return (LPVOID)NULL;
}

int main(int argc, char* argv[]) {

	char syscallStub[23];
	SIZE_T bytesWritten = 0;
	DWORD oldProtection = 0;
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;

	// variables for NtCreateFile
	OBJECT_ATTRIBUTES oa;
	HANDLE fileHandle = NULL;
	NTSTATUS status = NULL;
	UNICODE_STRING fileName;
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	RtlInitUnicodeString(&fileName, (PCWSTR)L"\\??\\c:\\temp\\temp.log");
	IO_STATUS_BLOCK osb;
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
	InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);



	//Get NTDLL address
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi;
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = mi.lpBaseOfDll;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + dosHeader->e_lfanew);
	DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
	PIMAGE_SECTION_HEADER textSection = section;
	PIMAGE_SECTION_HEADER rdataSection = section;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
	{

		if (strcmp((CHAR*)section->Name, (CHAR*)".rdata") == 0) {
			rdataSection = section;
			break;
		}
		section++;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)ntdllBase + exportDirRVA, rdataSection);
	//Get our real NTDLL syscall stub. Only do this once and then pass it around to avoid reading NTDLL every time 
	LPVOID ntdllSyscallPointer = GetFirstStub(exportDirectory, ntdllBase, textSection, rdataSection);
	//Modify our NtCreateFile syscall
	createObfuscatedSyscall(&NtCreateFile, ntdllSyscallPointer);

	status = NtCreateFile(&fileHandle, FILE_GENERIC_WRITE, &oa, &osb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status != STATUS_SUCCESS) {
		printf("Syscall failed...\n");
	}
	else {
		printf("Syscall succeeded!\n");
	}

	return 0;
}



void createObfuscatedSyscall(LPVOID SyscallFunction, LPVOID ntdllSyscallPointer) {
	//Get the address of the syscall instruction
	LPVOID syscallAddress = (char*)ntdllSyscallPointer + 18;

	//Construct our trampoline, logic taken from here
	//https://github.com/bats3c/EvtMute/blob/master/EvtMute/EvtMuteHook/dllmain.cpp#L57
	unsigned char jumpPrelude[] = { 0x49, 0xBB }; //mov r11
	unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF }; //placeholder where the address goes
	*(void**)(jumpAddress) = syscallAddress; //replace the address
	unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3 }; //jmp r11

	DWORD oldProtect = NULL;
	VirtualProtectEx(GetCurrentProcess(), SyscallFunction, 61 + 2 + 8 + 3, PAGE_EXECUTE_READWRITE, &oldProtect);

	memcpy((char*)SyscallFunction + 61, jumpPrelude, 2);
	memcpy((char*)SyscallFunction + 61 + 2, jumpAddress, sizeof(jumpAddress));
	memcpy((char*)SyscallFunction + 61 + 2 + 8, jumpEpilogue, 3);

	VirtualProtectEx(GetCurrentProcess(), SyscallFunction, 61 + 2 + 8 + 3, oldProtect, &oldProtect);

}

