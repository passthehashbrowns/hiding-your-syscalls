#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE


#include <Windows.h>
#include <stdio.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include "Header.h"
#include "offsets.h"

#pragma comment (lib, "Dbghelp.lib")

int const SYSCALL_STUB_SIZE = 23;

char* createObfuscatedSyscall(LPVOID SyscallFunction, LPVOID ntdllSyscallFunction);
BOOL resetNtdllProtection(LPVOID ntdllPointer, DWORD protection);


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


	LPVOID ntdllSyscallPointer = (DWORD_PTR)ntdllBase + NtAcceptConnectPortOffset;
	//Modify our NtCreateFile syscall
	NtCreateFile = createObfuscatedSyscall(&NtCreateFile10, ntdllSyscallPointer);

	status = NtCreateFile(&fileHandle, FILE_GENERIC_WRITE, &oa, &osb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status != STATUS_SUCCESS) {
		printf("Syscall failed...\n");
	}
	else {
		printf("Syscall succeeded!\n");
	}

	return 0;
}


char* createObfuscatedSyscall(LPVOID SyscallFunction, LPVOID ntdllSyscallPointer) {
	//Get our syscall stub
	char asmBuf[23];
	memcpy(asmBuf, SyscallFunction, 23);
	//Get the address of the syscall instruction
	LPVOID syscallAddress = (char*)ntdllSyscallPointer + 18;

	//Construct our trampoline, logic taken from here
	//https://github.com/bats3c/EvtMute/blob/master/EvtMute/EvtMuteHook/dllmain.cpp#L57
	unsigned char jumpPrelude[] = { 0x00, 0x49, 0xBB }; //mov r11
	unsigned char jumpAddress[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF }; //placeholder where the address goes
	*(void**)(jumpAddress) = syscallAddress; //replace the address
	unsigned char jumpEpilogue[] = { 0x41, 0xFF, 0xE3 , 0xC3 }; //jmp r11

	//Copy it all into a final buffer
	char finalSyscall[30];
	memcpy(finalSyscall, asmBuf, 7);
	memcpy(finalSyscall + 7, jumpPrelude, 3);
	memcpy(finalSyscall + 7 + 3, jumpAddress, sizeof(jumpAddress));
	memcpy(finalSyscall + 7 + 3 + 8, jumpEpilogue, 4);

	//Make sure that we can execute 
	DWORD oldProtect = NULL;
	VirtualProtectEx(GetCurrentProcess(), &finalSyscall, sizeof(finalSyscall), PAGE_EXECUTE_READWRITE, &oldProtect);

	return &finalSyscall;
}

//Restore the NTDLL syscall stub to the previous protection
BOOL resetNtdllProtection(LPVOID ntdllPointer, DWORD protection) {
	DWORD oldProtect = NULL;
	BOOL bSuccess = VirtualProtectEx(GetCurrentProcess(), ntdllPointer, SYSCALL_STUB_SIZE, protection, oldProtect);
	return bSuccess;

}
