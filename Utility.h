#pragma once

#include <Windows.h>
#include <TlHelp32.h>	//SNAPSHOT
#include <winnt.h>		//IMAGE_DOS_HEADER

//sizeof(_IMAGE_DOS_HEADER) == 60 bytes
//_IMAGE_DOS_HEADER.e_magig == MZ always
//_IMAGE_DOS_HEADER.e_lfanew(4bytes) - PE-header offset
//next 200 bytes - dos program

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

class Utility {
public:
	Utility();
	~Utility();

	//return vector of processes sorted by pId
	static DWORD GetProcesses(std::vector<PROCESSENTRY32>& processes, bool sort = false);
	
	static DWORD GetPorcessIdByName(const std::string& name);

	static HANDLE GetHandleByPid(DWORD pId);

	static HANDLE GetHandleByName(const std::string& name);

	static void EnableDebugPriv();

	static void ReadDosHeader(const std::string& name, PIMAGE_DOS_HEADER header);
	
};

