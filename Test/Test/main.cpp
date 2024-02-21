#include <Windows.h>
#include <iostream>

void* FindSign(char* addr);

int main() {
	HANDLE myHandle = GetModuleHandleA(NULL);
	if (myHandle == NULL) return -1;

	char* addr = nullptr;
	addr = (char*)myHandle;
	if (addr == NULL) return -1;
	
	DWORD64 pe = DWORD64(addr + 0x3C);

	auto signAddr = FindSign(addr);
	/*addr += *((DWORD*)&addr[0x3C]);*/
	PIMAGE_NT_HEADERS inh;
	inh = (IMAGE_NT_HEADERS*)signAddr;
	auto iamgeBase = inh->OptionalHeader.ImageBase;
	DWORD dwRVA = *(DWORD*)&inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	/*void* iidRva = (addr + 0x80);
	
	PIMAGE_IMPORT_DESCRIPTOR iid = (PIMAGE_IMPORT_DESCRIPTOR)iidRva;*/
	IMAGE_IMPORT_DESCRIPTOR* iid;
	iid = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)iamgeBase + dwRVA);
	
	

	printf_s("pe : %p \n", addr);
	printf_s("pe : %p \n", signAddr);

	return 0;
};

void* FindSign(char* addr) {
	while (true) {
		if (*addr == 0x50) {
			if (*(addr + 1) == 0x45) {
				return addr;
			};
		};
		addr++;
	};
};