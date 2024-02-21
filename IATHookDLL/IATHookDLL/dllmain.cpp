// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

BOOL WINAPI MySetWindowTextW(HWND hwnd, LPWSTR lpString);
BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew);

const char* dllTitle = "IATHookDLL";

HMODULE moduleHandle = NULL;
void* originFunc = NULL;

typedef  BOOL (WINAPI
    *MYSETWINDOWTEXT)(
    _In_ HWND hWnd,
    _In_opt_ LPCWSTR lpString);



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    //후킹 할 IAT 함수 구하는 코드 시작
    moduleHandle = GetModuleHandleA("user32.dll");
    if (moduleHandle == NULL) {
        MessageBoxA(NULL, "GetModule", dllTitle, NULL);
        return FALSE;
    };

    originFunc = GetProcAddress(moduleHandle, "SetWindowTextW");
    if (originFunc == NULL) {
        MessageBoxA(NULL, "GetProcAddress", dllTitle, NULL);
        return FALSE;
    };
    //후킹 할 IAT 함수 구하는 코드 끝

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Entered", "IATHookDLL", NULL);
        hook_iat("user32.dll", (PROC)originFunc, (PROC)MySetWindowTextW);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        //hook_iat("user32.dll", (PROC)MySetWindowTextW, (PROC)originFunc);
        break;
    }
    return TRUE;
}

BOOL WINAPI MySetWindowTextW(HWND hwnd, LPWSTR lpString) {
    const wchar_t* pNum = L"영일이삼사오육칠팔구";
    wchar_t temp[2] = { 0, };
    int i = 0, nLen = 0, nIndex = 0;

    nLen = wcslen(lpString);

    for (i = 0; i < nLen; i++) {
        if (L'0' <= lpString[i] && lpString[i] <= L'9') {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp);
            lpString[i] = pNum[nIndex];
        };
    };

    return ((MYSETWINDOWTEXT)originFunc)(hwnd, lpString);
};

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew) {
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_NT_HEADERS pinh;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect, dwRVA;
    char* pAddr;

    hMod = GetModuleHandle(NULL);
    pAddr = (char*)hMod;

    //32비트용
    /*pAddr += *((DWORD*)&pAddr[0x3C]);
    dwRVA = *((DWORD*)&pAddr[0x80]);
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);*/
    
    //64비트용
    pinh = (IMAGE_NT_HEADERS*)pAddr;
    dwRVA = pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)hMod + dwRVA);

    for (; pImportDesc->Name; pImportDesc++) {
        szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
        if (!_stricmp(szLibName, szDllName)) {
            //32비트용
            //pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
            pThunk = (PIMAGE_THUNK_DATA)((DWORD64)hMod + pImportDesc->FirstThunk);

            for (; pThunk->u1.Function; pThunk++) {
                VirtualProtect((LPVOID)&pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                //32비트용
                //pThunk->u1.Function = (DWORD)pfnNew;
                pThunk->u1.Function = (DWORD64)pfnNew;

                VirtualProtect((LPVOID)&pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);
                return TRUE;
            };
        };
    };
    return FALSE;
};

