#pragma once
#include <Windows.h>
#include <TlHelp32.h>

int GetProcID(wchar_t* exeName);
MODULEENTRY32 GetModule(DWORD dwProcID, wchar_t* moduleName);
double ElapsedTimeInSeconds(HANDLE hProcess);
LPCVOID PointerToFunction(std::string functionName, HANDLE hProcessIL2, MODULEENTRY32 moduleRSE);