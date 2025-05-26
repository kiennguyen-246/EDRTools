#include <windows.h>

#include <iostream>

#define HOOK_LIB L"HookLib.dll"
#define TARGET_LIB L"sechost.dll"

PVOID pDllContentBuffer;
PVOID pDllInjectedBase;
BYTE backupBuffer[5];
HANDLE hPipe;

typedef struct _IMAGE_BASE_RELOCATION_BLOCK_ENTRY {
  WORD wOffset : 12;
  WORD wType : 4;
} IMAGE_BASE_RELOCATION_BLOCK_ENTRY, *PIMAGE_BASE_RELOCATION_BLOCK_ENTRY;

BOOL reflectiveInject(std::wstring sDllPath, DWORD dwPid) {
  HANDLE hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
  if (hRemoteProcess == NULL) {
    DWORD dwError = GetLastError();
    std::wcout << L"OpenProcess failed with error: " << dwError << std::endl;
    return FALSE;
  }

  // 1. Read the DLL content to a buffer
  HANDLE hDllFile = CreateFile(sDllPath.c_str(), GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
  if (hDllFile == INVALID_HANDLE_VALUE) {
    DWORD dwError = GetLastError();
    std::wcout << L"CreateFile failed with error: " << dwError << std::endl;
    return FALSE;
  }
  DWORD dwDllFileSize = GetFileSize(hDllFile, NULL);
  if (dwDllFileSize == INVALID_FILE_SIZE) {
    DWORD dwError = GetLastError();
    std::wcout << L"GetFileSize failed with error: " << dwError << std::endl;
    CloseHandle(hDllFile);
    return FALSE;
  }
  pDllContentBuffer = HeapAlloc(GetProcessHeap(), 0, dwDllFileSize);
  if (pDllContentBuffer == NULL) {
    DWORD dwError = GetLastError();
    std::wcout << L"HeapAlloc failed with error: " << dwError << std::endl;
    CloseHandle(hDllFile);
    return FALSE;
  }
  DWORD dwBytesRead = 0;
  BOOL bRet =
      ReadFile(hDllFile, pDllContentBuffer, dwDllFileSize, &dwBytesRead, NULL);
  if (!bRet) {
    DWORD dwError = GetLastError();
    std::wcout << L"ReadFile failed with error: " << dwError << std::endl;
    CloseHandle(hDllFile);
    HeapFree(GetProcessHeap(), 0, pDllContentBuffer);
    return FALSE;
  }
  CloseHandle(hDllFile);

  // 2. Parse DLL content to get the SizeOfImage field
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllContentBuffer;
  PIMAGE_NT_HEADERS pNtHeader =
      (PIMAGE_NT_HEADERS)((PBYTE)pDllContentBuffer + pDosHeader->e_lfanew);
  DWORD dwSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;

  // 3. Allocate memory at BaseOfImage with the size of dwSizeOfImage
  HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
  ULONGLONG ullImageBase = (ULONGLONG)hKernel32;
  pDllInjectedBase = NULL;
  while (pDllInjectedBase == NULL) {
    pDllInjectedBase = VirtualAllocEx(
        hRemoteProcess, (PVOID)((PBYTE)ullImageBase), dwSizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // pDllInjectedBase =
    //     VirtualAllocEx(hRemoteProcess, NULL, dwSizeOfImage,
    //                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pDllInjectedBase == NULL) {
      DWORD dwError = GetLastError();
      if (dwError == ERROR_INVALID_ADDRESS) {
        ullImageBase -= 0x100000;
        continue;
      }
      std::wcout << L"VirtualAllocEx failed with error: " << dwError
                 << std::endl;
      HeapFree(GetProcessHeap(), 0, pDllContentBuffer);
      return FALSE;
    }
  }

  // 4. Copy the DLL headers and PE sections to the memory space allocated in
  // the last step

  // 4.1. Copy the headers
  WriteProcessMemory(hRemoteProcess, pDllInjectedBase, pDllContentBuffer,
                     pNtHeader->OptionalHeader.SizeOfHeaders, NULL);

  // 4.2. Copy the sections
  PIMAGE_SECTION_HEADER pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
  for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i) {
    WriteProcessMemory(hRemoteProcess,
                       (PVOID)((PBYTE)pDllInjectedBase +
                               pCurrentSectionHeader->VirtualAddress),
                       (PVOID)((PBYTE)pDllContentBuffer +
                               pCurrentSectionHeader->PointerToRawData),
                       pCurrentSectionHeader->SizeOfRawData, NULL);
    ++pCurrentSectionHeader;
  }

  // 5. Perform image base relocations
  // 5.1. Get the delta
  ULONGLONG ullDelta =
      (ULONGLONG)pDllInjectedBase - pNtHeader->OptionalHeader.ImageBase;

  // 5.2. Jump to the first relocation block
  PIMAGE_BASE_RELOCATION pRelocationTable =
      (PIMAGE_BASE_RELOCATION)((PBYTE)pDllInjectedBase +
                               pNtHeader->OptionalHeader
                                   .DataDirectory
                                       [IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                   .VirtualAddress);

  // 5.3. For each entries within, take the 12 lower bits, get the sum with
  // delta to get the new address
  DWORD dwRelocationBytesProceeded = 0;
  DWORD dwRelocationTableSize =
      pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .Size;
  while (dwRelocationBytesProceeded < dwRelocationTableSize) {
    PIMAGE_BASE_RELOCATION pCurrentBlockHeader =
        (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocationTable +
                                 dwRelocationBytesProceeded);

    IMAGE_BASE_RELOCATION currentBlockHeader;
    ReadProcessMemory(hRemoteProcess, pCurrentBlockHeader, &currentBlockHeader,
                      sizeof(IMAGE_BASE_RELOCATION), NULL);

    dwRelocationBytesProceeded += sizeof(IMAGE_BASE_RELOCATION);
    DWORD dwNumberOfEntries =
        (currentBlockHeader.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
        sizeof(IMAGE_BASE_RELOCATION_BLOCK_ENTRY);
    for (DWORD i = 0; i < dwNumberOfEntries; ++i) {
      PIMAGE_BASE_RELOCATION_BLOCK_ENTRY pCurrentBlockEntry =
          (PIMAGE_BASE_RELOCATION_BLOCK_ENTRY)((PBYTE)pRelocationTable +
                                               dwRelocationBytesProceeded);

      IMAGE_BASE_RELOCATION_BLOCK_ENTRY currentBlockEntry;
      ReadProcessMemory(hRemoteProcess, pCurrentBlockEntry, &currentBlockEntry,
                        sizeof(IMAGE_BASE_RELOCATION_BLOCK_ENTRY), NULL);
      dwRelocationBytesProceeded += sizeof(IMAGE_BASE_RELOCATION_BLOCK_ENTRY);
      if (currentBlockEntry.wType == 0) {
        continue;
      }
      DWORD dwRelocationOffset =
          currentBlockHeader.VirtualAddress + currentBlockEntry.wOffset;
      PDWORD pdwAddressToPatch = 0;
      ReadProcessMemory(hRemoteProcess,
                        (PVOID)((PBYTE)pDllInjectedBase + dwRelocationOffset),
                        &pdwAddressToPatch, sizeof(PDWORD), NULL);
      pdwAddressToPatch = (PDWORD)((ULONGLONG)pdwAddressToPatch + ullDelta);
      WriteProcessMemory(hRemoteProcess,
                         (PVOID)((PBYTE)pDllInjectedBase + dwRelocationOffset),
                         &pdwAddressToPatch, sizeof(PDWORD), NULL);
    }
  }

  // 6. Resolve the IAT
  // 6.1 Get the first import descriptor
  PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor =
      (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pDllInjectedBase +
                                 pNtHeader->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                     .VirtualAddress);

  // 6.2. Iterate over import descriptors
  HMODULE hImportedLib = NULL;
  // HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
  while (TRUE) {
    IMAGE_IMPORT_DESCRIPTOR currentImportDescriptor;
    ReadProcessMemory(hRemoteProcess, pImportDescriptor,
                      &currentImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR),
                      NULL);
    if (currentImportDescriptor.Name == 0) {
      break;
    }

    // 6.2.1. Load the imported library
    PCHAR pcImportedLibName =
        (PCHAR)((PBYTE)pDllInjectedBase + currentImportDescriptor.Name);
    CHAR pcCopiedImportedLibName[MAX_PATH];
    ZeroMemory(pcCopiedImportedLibName, sizeof(pcCopiedImportedLibName));
    ReadProcessMemory(hRemoteProcess, pcImportedLibName,
                      pcCopiedImportedLibName, MAX_PATH, NULL);

    hImportedLib = LoadLibraryA(pcCopiedImportedLibName);
    if (hImportedLib == NULL) {
      DWORD dwError = GetLastError();
      std::wcout << L"LoadLibraryA for library " << pcCopiedImportedLibName
                 << " failed with error: " << dwError << std::endl;
      continue;
    }

    FARPROC fpLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    DWORD dwRemoteTid = 0;
    HANDLE hRemoteThread = CreateRemoteThread(
        hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fpLoadLibrary,
        pcImportedLibName, 0, &dwRemoteTid);

    // 6.2.2. Get all thunks in the library
    PIMAGE_THUNK_DATA pThunkData =
        (PIMAGE_THUNK_DATA)((PBYTE)pDllInjectedBase +
                            currentImportDescriptor.FirstThunk);

    // 6.2.3. For each thunk, resolve its address using GetProcAddress(), then
    // put it into the IAT
    while (TRUE) {
      IMAGE_THUNK_DATA currentThunkData;
      ReadProcessMemory(hRemoteProcess, pThunkData, &currentThunkData,
                        sizeof(IMAGE_THUNK_DATA), NULL);
      if (currentThunkData.u1.AddressOfData == 0) {
        break;
      }

      if (IMAGE_SNAP_BY_ORDINAL(currentThunkData.u1.Ordinal)) {
        PCHAR pcFunctionOrdinal =
            (PCHAR)IMAGE_ORDINAL(currentThunkData.u1.Ordinal);
        currentThunkData.u1.Function =
            (ULONGLONG)GetProcAddress(hImportedLib, pcFunctionOrdinal);
      } else {
        PIMAGE_IMPORT_BY_NAME pImportByName =
            (PIMAGE_IMPORT_BY_NAME)((PBYTE)pDllInjectedBase +
                                    currentThunkData.u1.AddressOfData);
        CHAR pcCopiedFunctionName[MAX_PATH];
        ZeroMemory(pcCopiedFunctionName, sizeof(pcCopiedFunctionName));
        ReadProcessMemory(hRemoteProcess, pImportByName->Name,
                          pcCopiedFunctionName, MAX_PATH, NULL);
        currentThunkData.u1.Function =
            (ULONGLONG)GetProcAddress(hImportedLib, pcCopiedFunctionName);
      }
      WriteProcessMemory(hRemoteProcess, pThunkData, &currentThunkData,
                         sizeof(IMAGE_THUNK_DATA), NULL);
      ++pThunkData;
    }
    ++pImportDescriptor;
  }

  // 7. Call the DLL's entry point
  typedef BOOL(WINAPI * FPDLLMAIN)(HINSTANCE, DWORD, LPVOID);
  FPDLLMAIN fpDllMain =
      (FPDLLMAIN)((PBYTE)pDllInjectedBase +
                  pNtHeader->OptionalHeader.AddressOfEntryPoint);

  CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fpDllMain,
                     (HINSTANCE)pDllInjectedBase, 0, NULL);

  return TRUE;
}

std::string wstringToString(std::wstring ws) {
  std::string s = "";
  for (auto i : ws) s.push_back((CHAR)i);
  return s;
}

BOOL inlineHook(std::wstring wsTargetLibName, std::wstring wsTargetFuncName,
                std::wstring wsHookLibName, std::wstring wsHookFuncName,
                DWORD dwPid) {
  HANDLE hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
  if (hRemoteProcess == NULL) {
    DWORD dwError = GetLastError();
    std::wcout << L"OpenProcess failed with error: " << dwError << std::endl;
    return FALSE;
  }

  // 1. Identify the address of the target function
  HMODULE hHookLib = LoadLibrary(wsHookLibName.c_str());
  HMODULE hTargetLib = LoadLibrary(wsTargetLibName.c_str());
  FARPROC fpGetModuleAddress = GetProcAddress(hHookLib, "getModuleAddress");

  std::string sLibName = wstringToString(wsTargetLibName);
  std::string sFuncName = wstringToString(wsTargetFuncName);
  PCHAR pRemoteLibName = (PCHAR)VirtualAllocEx(
      hRemoteProcess, NULL, sLibName.size(), MEM_COMMIT, PAGE_READWRITE);
  WriteProcessMemory(hRemoteProcess, pRemoteLibName, &sLibName[0],
                     sLibName.size(), NULL);
  HANDLE hRemoteThread = CreateRemoteThread(
      hRemoteProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE)((ULONGLONG)pDllInjectedBase +
                               ((ULONGLONG)fpGetModuleAddress -
                                (ULONGLONG)hHookLib)),
      pRemoteLibName, 0, NULL);
  if (hRemoteThread == NULL) {
    wprintf(L"CreateRemoteThread failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }
  WaitForSingleObject(hRemoteThread, INFINITE);
  CloseHandle(hRemoteThread);

  BYTE abBuffer[64];
  DWORD dwBytesRead = 0;
  ZeroMemory(abBuffer, 64);
  BOOL result = ReadFile(hPipe, abBuffer, 64, &dwBytesRead, NULL);
  if (!result) {
    wprintf(L"ReadFile failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }
  ULONGLONG ullRemoteTargetLibBase = 0;
  for (int i = 0; i < 64; i++) {
    ullRemoteTargetLibBase = ullRemoteTargetLibBase * 2 + (abBuffer[i] - '0');
  }
  PVOID pRemoteTargetLibBase = (PVOID)ullRemoteTargetLibBase;

  FARPROC fpLocalTargetFunctionAddress =
      GetProcAddress(hTargetLib, wstringToString(wsTargetFuncName).c_str());
  PVOID pRemoteTargetFunc = (PVOID)((ULONGLONG)pRemoteTargetLibBase +
                                    ((ULONGLONG)fpLocalTargetFunctionAddress -
                                     (ULONGLONG)hTargetLib));

  // 2. Create and initialize the trampolines
  // 2.1. Create the trampoline
  PBYTE pbRemoteTrampoline = NULL;
  HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
  ULONGLONG ullRemoteAllocAddress = (ULONGLONG)hKernel32;
  while (pbRemoteTrampoline == NULL) {
    pbRemoteTrampoline =
        (PBYTE)VirtualAllocEx(hRemoteProcess, (PVOID)ullRemoteAllocAddress, 10,
                              MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pbRemoteTrampoline == NULL) {
      ullRemoteAllocAddress -= 0x100000;
    }
  }
  BYTE abLocalTrampolineBuffer[10];

  // 2.2. Load the first 5 bytes of the trampoline
  ReadProcessMemory(hRemoteProcess, pRemoteTargetFunc, abLocalTrampolineBuffer,
                    5, NULL);
  if (abLocalTrampolineBuffer[0] != 0xe9) {
    // 2.2.1. If it is not a jump instruction,  load "jmp <target address + 5>"
    // at the rest of the buffer
    abLocalTrampolineBuffer[5] = 0xe9;
    INT iJumpOffset =
        (INT)((LONGLONG)pRemoteTargetFunc - (LONGLONG)pbRemoteTrampoline - 5);
    for (int i = 0; i < 4; ++i) {
      abLocalTrampolineBuffer[i + 6] =
          (((ULONGLONG)(iJumpOffset) + 5) >> (8 * i)) & 0xff;
    }
  } else {
    // 2.2.2. If it is a jump instruction, change the offset to have the correct
    // jump
    ULONGLONG ullJumpTargetAddress = 0;
    INT iJumpOffset = 0;
    for (int i = 0; i < 4; ++i) {
      iJumpOffset += (abLocalTrampolineBuffer[i + 1] << (8 * i));
    }
    ullJumpTargetAddress = (ULONGLONG)pRemoteTargetFunc + 5 + iJumpOffset;
    INT iNewJumpOffset = (INT)((LONGLONG)ullJumpTargetAddress -
                               (LONGLONG)pbRemoteTrampoline - 5);

    abLocalTrampolineBuffer[0] = 0xe9;
    for (int i = 0; i < 4; ++i) {
      abLocalTrampolineBuffer[i + 1] = (iNewJumpOffset >> (8 * i)) & 0xff;
    }
    // abLocalTrampolineBuffer[5] = 0xe9;
    // iJumpOffset =
    //     (LONGLONG)pRemoteTargetFunc - (LONGLONG)pbRemoteTrampoline - 5;
    // for (int i = 0; i < 4; ++i) {
    //   abLocalTrampolineBuffer[i + 6] =
    //       (((ULONGLONG)(iJumpOffset) + 5) >> (8 * i)) & 0xff;
    // }
  }

  // 2.4. Commit the changes
  result = WriteProcessMemory(hRemoteProcess, pbRemoteTrampoline,
                              abLocalTrampolineBuffer, 10, NULL);
  if (!result) {
    wprintf(L"WriteProcessMemory failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  // 3. Send the location of the second trampoline to the injected library
  ZeroMemory(abBuffer, 64);
  for (int i = 0; i < 63; i++) {
    abBuffer[63 - i] = (((ULONGLONG)(pbRemoteTrampoline) >> i) & 1) + '0';
  }
  DWORD dwBytesWritten = 0;
  result = WriteFile(hPipe, abBuffer, 64, &dwBytesWritten, NULL);
  if (!result) {
    wprintf(L"WriteFile failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  // 4. Overwrite the first 5 bytes of the target function to "jmp <offset to
  // hooked function>
  FARPROC fpHookFunc =
      GetProcAddress(hHookLib, wstringToString(wsHookFuncName).c_str());
  PVOID pRemoteHookFunc =
      (PVOID)((ULONGLONG)pDllInjectedBase +
              ((ULONGLONG)fpHookFunc - (ULONGLONG)hHookLib));

  BYTE abLocalOverwriteBuffer[5];
  abLocalOverwriteBuffer[0] = 0xe9;
  INT iJumpOffset =
      (INT)((LONGLONG)pRemoteHookFunc - (LONGLONG)pRemoteTargetFunc - 5);
  for (int i = 0; i < 4; ++i) {
    abLocalOverwriteBuffer[i + 1] =
        ((ULONGLONG)(iJumpOffset) >> (8 * i)) & 0xff;
  }

  DWORD dwOldProtect = 0;
  result = VirtualProtectEx(hRemoteProcess, pRemoteTargetFunc, 5,
                            PAGE_EXECUTE_READWRITE, &dwOldProtect);
  if (!result) {
    wprintf(L"VirtualProtectEx failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  result = ReadProcessMemory(hRemoteProcess, pRemoteTargetFunc, backupBuffer, 5,
                             NULL);
  if (!result) {
    wprintf(L"ReadProcessMemory failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  result = WriteProcessMemory(hRemoteProcess, pRemoteTargetFunc,
                              abLocalOverwriteBuffer, 5, NULL);
  if (!result) {
    wprintf(L"WriteProcessMemory failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  result = VirtualProtectEx(hRemoteProcess, pRemoteTargetFunc, 5, dwOldProtect,
                            &dwOldProtect);
  if (!result) {
    wprintf(L"VirtualProtectEx failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  FreeLibrary(hTargetLib);
  FreeLibrary(hHookLib);

  return TRUE;
}

BOOL disableInlineHook(std::wstring wsLibName, std::wstring wsFuncName,
                       DWORD dwPid) {
  HANDLE hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
  if (hRemoteProcess == NULL) {
    DWORD dwError = GetLastError();
    std::wcout << L"OpenProcess failed with error: " << dwError << std::endl;
    return FALSE;
  }

  // 1. Identify the address of the target function
  HMODULE hHookLib = LoadLibrary(L"FakeNotification.dll");
  HMODULE hTargetLib = LoadLibrary(wsLibName.c_str());
  FARPROC fpGetModuleAddress = GetProcAddress(hHookLib, "getModuleAddress");

  std::string sLibName = wstringToString(wsLibName);
  std::string sFuncName = wstringToString(wsFuncName);
  PCHAR pRemoteLibName = (PCHAR)VirtualAllocEx(
      hRemoteProcess, NULL, sLibName.size(), MEM_COMMIT, PAGE_READWRITE);
  WriteProcessMemory(hRemoteProcess, pRemoteLibName, &sLibName[0],
                     sLibName.size(), NULL);
  HANDLE hRemoteThread = CreateRemoteThread(
      hRemoteProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE)((ULONGLONG)pDllInjectedBase +
                               ((ULONGLONG)fpGetModuleAddress -
                                (ULONGLONG)hHookLib)),
      pRemoteLibName, 0, NULL);
  if (hRemoteThread == NULL) {
    wprintf(L"CreateRemoteThread failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }
  WaitForSingleObject(hRemoteThread, INFINITE);
  CloseHandle(hRemoteThread);

  BYTE abBuffer[64];
  DWORD dwBytesRead = 0;
  ZeroMemory(abBuffer, 64);
  BOOL result = ReadFile(hPipe, abBuffer, 64, &dwBytesRead, NULL);
  if (!result) {
    wprintf(L"ReadFile failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }
  ULONGLONG ullRemoteTargetLibBase = 0;
  for (int i = 0; i < 64; i++) {
    ullRemoteTargetLibBase = ullRemoteTargetLibBase * 2 + (abBuffer[i] - '0');
  }
  PVOID pRemoteTargetLibBase = (PVOID)ullRemoteTargetLibBase;

  FARPROC fpLocalTargetFunctionAddress =
      GetProcAddress(hTargetLib, wstringToString(wsFuncName).c_str());
  PVOID pRemoteTargetFunc = (PVOID)((ULONGLONG)pRemoteTargetLibBase +
                                    ((ULONGLONG)fpLocalTargetFunctionAddress -
                                     (ULONGLONG)hTargetLib));

  BYTE abLocalOverwriteBuffer[5];
  abLocalOverwriteBuffer[0] = 0xe9;

  DWORD dwOldProtect = 0;
  result = VirtualProtectEx(hRemoteProcess, pRemoteTargetFunc, 5,
                            PAGE_EXECUTE_READWRITE, &dwOldProtect);
  if (!result) {
    wprintf(L"VirtualProtectEx failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  result = WriteProcessMemory(hRemoteProcess, pRemoteTargetFunc, backupBuffer,
                              5, NULL);
  if (!result) {
    wprintf(L"WriteProcessMemory failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  result = VirtualProtectEx(hRemoteProcess, pRemoteTargetFunc, 5, dwOldProtect,
                            &dwOldProtect);
  if (!result) {
    wprintf(L"VirtualProtectEx failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
  }

  FreeLibrary(hTargetLib);
  FreeLibrary(hHookLib);

  return TRUE;
}

VOID connectThreadRoutine() { ConnectNamedPipe(hPipe, NULL); }

int main() {
  HMODULE hSecHost = LoadLibrary(TARGET_LIB);
  if (!hSecHost) {
    wprintf(L"LoadLibrary failed %d, at file %ws, function %ws, line %d",
            GetLastError(), __FILEW__, __FUNCTIONW__, __LINE__);
    return 0;
  }

  hPipe = CreateNamedPipe(L"\\\\.\\pipe\\SecHostHook", PIPE_ACCESS_DUPLEX,
                          PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                          PIPE_UNLIMITED_INSTANCES, 64, 64, 0, NULL);
  HANDLE hThread = CreateThread(
      NULL, 0, (LPTHREAD_START_ROUTINE)connectThreadRoutine, NULL, 0, NULL);

  DWORD dwPid = GetCurrentProcessId();
  if (!reflectiveInject(HOOK_LIB, dwPid)) {
    std::wcout << "Reflective injecting DLL failed\n";
    return 1;
  }

  WaitForSingleObject(hThread, INFINITE);
  CloseHandle(hThread);

  BOOL isHooked = FALSE;
  while (TRUE) {
    if (!isHooked) {
      INT messageId =
          MessageBox(NULL, L"Press OK to enable hook", L"SecHostHook",
                     MB_OKCANCEL | MB_ICONINFORMATION);
      if (messageId == IDCANCEL) {
        std::wcout << "Exiting...\n";
        break;
      }
      if (!inlineHook(TARGET_LIB, L"ControlService", HOOK_LIB,
                      L"HookedControlService", dwPid)) {
        std::wcout << "Hooking failed\n";
        return 1;
      }
      isHooked ^= 1;
    } else {
      INT messageId =
          MessageBox(NULL, L"Press OK to enable hook", L"SecHostHook",
                     MB_OKCANCEL | MB_ICONINFORMATION);
      if (messageId == IDCANCEL) {
        std::wcout << "Exiting...\n";
        break;
      }
      if (!disableInlineHook(TARGET_LIB, L"ControlService", dwPid)) {
        std::wcout << "Disabling hook failed\n";
        return 1;
      }
      isHooked ^= 1;
    }
  }

  CloseHandle(hPipe);
  HeapFree(GetProcessHeap(), 0, pDllContentBuffer);

  FreeLibrary(hSecHost);
}
