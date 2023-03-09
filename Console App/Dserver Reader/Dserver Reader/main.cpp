using namespace std;
#include <iostream>
#include "ProcessTools.h"

char originalLine[8];
HANDLE hProcess;
MODULEENTRY32W moduleRSE;
LPCVOID aeroplaneClearAddress;
LPVOID codeCaveAddress;
const int memSize = 1000;

bool FindFunctions()
{
	wchar_t* exeName = (wchar_t*)L"DServer.exe";
	int processID = GetProcID(exeName);

	//Get handle by OpenProcess
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
	if (hProcess == 0)
		return 1;

	//RSE.dll
	moduleRSE = GetModule(processID, (wchar_t*)L"RSE.dll");
	if (moduleRSE.dwSize == 0)
		return 1;

	aeroplaneClearAddress = PointerToFunction("init@CAeroplane", hProcess, moduleRSE);

	if (aeroplaneClearAddress != 0) {
		return 0;
	}

	return 1;
}

bool Injection()
{
	uintptr_t src = (uintptr_t)aeroplaneClearAddress;

	size_t bytesWritten = 0;
	ReadProcessMemory(hProcess, (LPVOID)aeroplaneClearAddress, &originalLine, 8, &bytesWritten);

	//0x09 is the byte form of "jmp", assembly language to jump to a location. Note this is a x86 instruction (it can only jump +- 2gb of memory)
	BYTE jump = 0xE9;

	//write jump opcode
	WriteProcessMemory(hProcess, (LPVOID)src, &jump, sizeof(jump), &bytesWritten);
	//work out relative address
	//cave - hook - 5 (jmp)
	//Relative address. Using 32bit data type due to close nature of jump
	uintptr_t relativeAddress = (uintptr_t)codeCaveAddress - src - 5;
	LPVOID rA = (LPVOID)relativeAddress;
	WriteProcessMemory(hProcess, (LPVOID)(src + 0x01), &relativeAddress, sizeof(DWORD), &bytesWritten);
	//we need to add a nope to pad out memory so we jump back at same point we left
	BYTE nops[3] = { 0x90, 0x90, 0x90 };
	//add a nop
	WriteProcessMemory(hProcess, (LPVOID)(src + 0x01 + sizeof(DWORD)), &nops, sizeof(nops), &bytesWritten);

	return 0;
}

bool WriteCodeCave()
{
	uintptr_t src = (uintptr_t)aeroplaneClearAddress;
	size_t totalWritten = 0;
	//toCave = (LPVOID)((uintptr_t)(toCave)+0x00);//0x00 - plane type at start of cave
	//cave - where we put our own code alongside the original
	size_t bytesWritten = 0;

	BYTE cmp[178] = {
		//push r14 (original line)
		0x41, 0x56,
		//sub rsp, 30 (original line)
		0x48, 0x83 ,0xEC ,0x30,
		//push rdx
		0x52,
		//push rbx
		0x53,
		//push r8
		0x41, 0x50,
		//push r9
		0x41, 0x51,
		//push r10
		0x41, 0x52,
		//mov r8, codecave addy +100
		0x4C, 0x8B ,0x05 ,0xEB ,0x00,0x00, 0x00,
		//cmp rax, 00
		0x48, 0x83, 0xF8, 0x00,
		//jne
		0x0F,0x85, 0x1A, 0x00, 0x00, 0x00,
		//lea, [r8*8 + codecave addy +1024]
		0x4A, 0x8D, 0x1C, 0xD5, 0x24, 0x10, 0x97, 0x00,
		//mov [rbx], rcx
		0x48, 0x89, 0x0B,
		//inc r8
		0x49, 0xFF, 0xC0,
		//mov [codecave addy +100], r8
		0x4C, 0x89, 0x05, 0xCC, 0x00, 0x00, 0x00,
		//jmp
		0xE9, 0x6C, 0x00, 0x00, 0x00,
		//mov r9, 0
		0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//mov r10, 0
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//cmp r8, r9
		0x4D, 0x39, 0xC8,
		//jmp
		0x0F, 0x84, 0x33, 0x00, 0x00, 0x00,
		//lea rbx,[r9*8+codecave addy +1024]
		0x4A, 0x8D, 0x1C, 0xCD, 0x24, 0x10, 0x97, 0x00,
		//cmp rcx, rbx
		0x48, 0x39, 0xD9,
		//jne
		0x0F, 0x85, 0x05, 0x00, 0x00, 0x00,
		//inc r9
		0x49 ,0xFF, 0xC1,
		//jmp
		0xEB, 0xE1,
		//lea 
		0x4A, 0x8D, 0x1C, 0xD5, 0x00, 0x02, 0xC2, 0x07,
		//mov rcx, rbx
		0x48, 0x8B, 0xCB,
		//inc r9
		0x49, 0xFF, 0xC1,
		//inc r10
		0x49, 0xFF, 0xC2,
		//jmp
		0xEB, 0xCE,
		//mov r9, 0
		0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//cmp r10, r9
		0x4D, 0x39, 0xCA,
		//je
		0x0F, 0x84,	0x13, 0x00, 0x00, 0x00,
		//lea
		0x4A, 0x8D, 0x1C, 0xCD, 0x00, 0x02, 0xC2, 0x07,
		//lea
		0x4A, 0x8D, 0x14, 0xCD, 0x20, 0x01, 0xC2, 0x07,
		//inc r9
		0x49, 0xFF, 0xC1,
		//pop r10
		0x41, 0x5A,
		//pop r9
		0x41, 0x59,
		//pop r8
		0x41, 0x58,
		//pop rbx
		0x5B,
		//pop rdx
		0x5A,
		//jmp to Areoplane.clear()
		0xE9, 0x74, 0x42, 0xF1, 0xF9
	};

	//first of all write the original function back in
	//and write orignal back in after our code
	WriteProcessMemory(hProcess, codeCaveAddress, &originalLine, 8, &bytesWritten);//5 is enough for the jump plus address
	totalWritten += bytesWritten;

	//only read address from rcx if rax == 0
	BYTE cmp[4] = { 0x48, 0x83, 0xF8, 0x00 };///???? player is 01, all is 00
	WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)(codeCaveAddress)+totalWritten), cmp, sizeof(cmp), &bytesWritten);
	totalWritten += bytesWritten;

	//jump short if equal - 
	BYTE je[2] = { 0x74, 0x07 };///???? player is 01, all is 00
	WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)(codeCaveAddress)+totalWritten), je, sizeof(je), &bytesWritten);
	totalWritten += bytesWritten;
	//copy rcx to code cave plus 200 - Use cheat engine to view the assembly
	BYTE rcxToMem[7] = { 0x48, 0x89, 0x0D, 0xEB, 0x01, 0x00, 0x00 };
	WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)(codeCaveAddress)+totalWritten), rcxToMem, sizeof(rcxToMem), &bytesWritten);
	totalWritten += bytesWritten;

	//jump to return address
	BYTE jump = 0xE9;
	//write 0x09 (jmp) 
	WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)(codeCaveAddress)+totalWritten), &jump, sizeof(jump), &bytesWritten);
	totalWritten += bytesWritten;
	//bytes written takes us back to start of "GetPlaneType" function, and we want to jump in at +8 
	DWORD returnAddress = (uintptr_t)(src - ((uintptr_t)codeCaveAddress + (totalWritten - 4)));//+4, ...still trial and error for this
	WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)(codeCaveAddress)+totalWritten), &returnAddress, sizeof(returnAddress), &bytesWritten);

	return 0;
}

bool Hook()//(HANDLE hProcess, void* pSrc, size_t size, LPVOID codeCaveAddress)
{
	//save old read/write access to put back to how it was later
	DWORD dwOld;
	LPVOID pSrc = (void*)(aeroplaneClearAddress);
	if (!VirtualProtectEx(hProcess, pSrc, memSize, PAGE_EXECUTE_READWRITE, &dwOld))
		return 0;

	uintptr_t src = (uintptr_t)pSrc;
	//insert jump in to original code
	Injection();

	//write out own process in our own allocated memory - 
	WriteCodeCave();

	//put write protections back to what they were before we injected
	VirtualProtectEx(hProcess, pSrc, memSize, dwOld, &dwOld);

	//return the start of our allocated memory struct
	return 0;
}

LPVOID AllocateMemoryUp(HANDLE hProcess, uintptr_t src)
{
	//to return, the address where we found the memory
	LPVOID toCave = 0;

	//find unallocated memory
	MEMORY_BASIC_INFORMATION mbi;

	size_t size = 0x2048;

	for (SIZE_T addr = src; addr < src + 2147483648; addr += size)
	{
		if (!VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)))
		{
			break;
		}
		//scan through until FREE block is discovered
		if (mbi.State == MEM_FREE)
		{
			if (toCave = VirtualAllocEx(hProcess, mbi.BaseAddress, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
			{
				return toCave;
			}
		}
	}

	return 0;
}

bool FindCodeCave()
{
	size_t bytesWritten = 0;
	char originalLine[8];//7 for mov inst, 1 for ret
	//create cave
	codeCaveAddress = AllocateMemoryUp(hProcess, (uintptr_t)moduleRSE.modBaseAddr);

	if (codeCaveAddress == 0)
		return 1;

	return 0;
}

void main()
{
	//The plan:
	//Find function that fires once on each plane spawn
	//Find function Aeroplane.Clear
	//Create codecave in dserver memory (and remember where this address is)
	//Hook above functions and reroute code flow to codecave (and back again)
	//count spawns with counter in assembly
	//add spawned plane addr to a list in dserver memory
	//decount with aeroplane.clear()
	//remove plane from list (rebuild list)

	//once hooked run update loop to read dserver memory, the hooks will update the list in dserver memory, all we need to is read the list

	if (FindFunctions() != 0) {
		std::cout << "Error Finding Function" << endl;
		return;
	}
	std::cout << "Aeroplane.Clear() Found at " << aeroplaneClearAddress << endl;

	if (FindCodeCave() != 0) {
		std::cout << "Error Finding Codecave" << endl;
		return;
	}

	std::cout << "CodeCave Address: " << codeCaveAddress << endl;

	if (WriteCodeCave() != 0) {
		std::cout << "Error Writing Codecave";
		return;
	}

	if (Injection() != 0) {
		std::cout << "Error Injecting";
		return;
	}

	return;
}

//set player presence rcx is plane struct
