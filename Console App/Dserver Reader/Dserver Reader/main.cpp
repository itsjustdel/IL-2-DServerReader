// Dserver Reader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "ProcessTools.h"

LPCVOID FindFunctions() 
{
	
	wchar_t* exeName = (wchar_t*)L"Il-2.exe";
	int processID = GetProcID(exeName);

	//Get handle by OpenProcess
	HANDLE hProcessIL2 = OpenProcess(PROCESS_ALL_ACCESS, false, processID); //PROCESS_ALL_ACCESS needed to create code cave
	if (hProcessIL2 == 0)
		return 0;


	//RSE.dll
	MODULEENTRY32W moduleRSE = GetModule(processID, (wchar_t*)L"RSE.dll");
	if (moduleRSE.dwSize == 0)
		return 0;

	LPCVOID funcAddress = PointerToFunction("setPlayerPresence", hProcessIL2, moduleRSE);

	if (funcAddress != 0) {
		std::cout << "Found at " << funcAddress;
		return funcAddress;
	 }

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
		return;
	}

	std::cout << "Error";
	return;
}
