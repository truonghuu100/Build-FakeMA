#include <windows.h>
#include <iphlpapi.h>
#include "MinHook.h"

#pragma comment(lib, "iphlpapi.lib")

typedef DWORD(WINAPI* PGET_ADAPTERS_INFO)(PIP_ADAPTER_INFO, PULONG);
PGET_ADAPTERS_INFO OriginalGetAdaptersInfo = NULL;

DWORD WINAPI HookedGetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) {
    DWORD result = OriginalGetAdaptersInfo(pAdapterInfo, pOutBufLen);
    if (result == ERROR_SUCCESS && pAdapterInfo != NULL) {
        PIP_ADAPTER_INFO pCurrent = pAdapterInfo;
        while (pCurrent) {
            pCurrent->Address[0] = 0x02; pCurrent->Address[1] = 0xA1;
            pCurrent->Address[2] = 0xB2; pCurrent->Address[3] = 0xC3;
            pCurrent->Address[4] = 0xD4; pCurrent->Address[5] = 0xE5;
            pCurrent->AddressLength = 6;
            pCurrent = pCurrent->Next;
        }
    }
    return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        MH_Initialize();
        MH_CreateHookApi(L"iphlpapi.dll", "GetAdaptersInfo", &HookedGetAdaptersInfo, (LPVOID*)&OriginalGetAdaptersInfo);
        MH_EnableHook(MH_ALL_HOOKS);
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
