#pragma once

#include <Windows.h>
#include <TlHelp32.h>	//SNAPSHOT
#include <winnt.h>		//IMAGE_DOS_HEADER

//sizeof(_IMAGE_DOS_HEADER) == 64 bytes
//_IMAGE_DOS_HEADER.e_magic == MZ always
//_IMAGE_DOS_HEADER.e_lfanew(4bytes) - PE-header offset


//next 200(?) bytes - dos stub


//PE HEADER
//4bytes - signature
//20bytes - file header
//??bytes - optional header

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

	static HANDLE GetHandleByPid(const DWORD pId);

	static HANDLE GetHandleByName(const std::string& name);

	static void EnableDebugPriv();

	static void ReadDosHeader(const std::string& name, IMAGE_DOS_HEADER* pDosHeader);

	static void ReadPEHeader(const std::string& name, const LONG addr, PIMAGE_NT_HEADERS pPeHeader);

	static int GetFileSize(const std::string& name);
	
};

