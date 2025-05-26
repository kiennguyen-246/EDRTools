// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

typedef BOOL (*ControlService_t)(SC_HANDLE, DWORD, LPSERVICE_STATUS);

HANDLE hPipe;
ControlService_t fpControlService;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  // hHookedLibrary = GetModuleHandle(L"Notification.dll");
  hPipe = CreateFile(L"\\\\.\\pipe\\SecHostHook", GENERIC_READ | GENERIC_WRITE,
                     0, NULL, OPEN_EXISTING, 0, NULL);
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}

extern "C" {
/* Hook function */
__declspec(dllexport) BOOL
hookedControlService(_In_ SC_HANDLE hService, _In_ DWORD dwControl,
                     _Out_ LPSERVICE_STATUS lpServiceStatus) {
  wprintf(L"Hooked ControlService called with hService: %p, dwControl: %lu\n",
          hService, dwControl);

  BYTE abBuffer[64];
  DWORD dwBytesRead = 0;
  ZeroMemory(abBuffer, 64);
  if (!fpControlService) {
    BOOL result = ReadFile(hPipe, abBuffer, 64, &dwBytesRead, NULL);
    if (!result) {
      wprintf(L"ReadFile failed %d, at file %ws, function %ws, line %d",
              GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
    }
    ULONGLONG ullFunctionPoint = 0;
    for (int i = 0; i < 64; i++)
      ullFunctionPoint = ullFunctionPoint * 2 + (abBuffer[i] - '0');
    fpControlService = (ControlService_t)(ullFunctionPoint);
    // MessageBox(
    //     NULL,
    //     std::format(L"Function pointer: 0x{:16x}", ullFunctionPoint).c_str(),
    //     L"fakeNotify", MB_OK | MB_ICONASTERISK);
  }

  return (fpControlService)(hService, dwControl, lpServiceStatus);
}

/* Get the target image base */
__declspec(dllexport) void findLoadProcessImageBase() {
  HMODULE hLoadProcessImageBase = GetModuleHandle(NULL);
  if (!hLoadProcessImageBase) {
    wprintf(L"GetModuleHandle failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }
  CHAR abBuffer[64];
  ZeroMemory(abBuffer, 64);
  for (int i = 0; i < 63; i++) {
    abBuffer[63 - i] = (((ULONGLONG)(hLoadProcessImageBase) >> i) & 1) + '0';
  }
  DWORD dwBytesWritten = 0;
  WriteFile(hPipe, abBuffer, 64, &dwBytesWritten, NULL);
}

/* Get the load base of some modules in the target process */
__declspec(dllexport) void getModuleAddress(CHAR* pcModuleName) {
  HMODULE hLib = GetModuleHandleA(pcModuleName);
  if (!hLib) {
    DWORD dwErr = GetLastError();
    wprintf(L"GetModuleHandle failed %d, at file %ws, function %ws, line %d",
            dwErr, __FILEW__, __FUNCTIONW__, __LINE__);
  }
  CHAR abBuffer[64];
  ZeroMemory(abBuffer, 64);
  for (int i = 0; i < 63; i++) {
    abBuffer[63 - i] = (((ULONGLONG)(hLib) >> i) & 1) + '0';
  }
  DWORD dwBytesWritten = 0;
  if (!WriteFile(hPipe, abBuffer, 64, &dwBytesWritten, NULL)) {
    DWORD dwErr = GetLastError();
    wprintf(L"WriteFile failed %d, at file %ws, function %ws, line %d", dwErr,
            __FILEW__, __FUNCTIONW__, __LINE__);
  }
}
}