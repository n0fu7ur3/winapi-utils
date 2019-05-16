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
#include <memory>

class HandleRAII {
	HANDLE mHandle;
public:
	HandleRAII(HANDLE h) : mHandle(h) {
		std::cout << "HANDLE: " << h << " ";
		std::cout << "captured" << std::endl;
	}
	~HandleRAII() {
		std::cout << "HANDLE: " << mHandle << " ";
			CloseHandle(mHandle);
		std::cout << "closed" << std::endl;
	}
	HANDLE Get() {
		return mHandle;
	}
};

class Utility {
public:
	Utility();
	~Utility();

	static void EnableDebugPriv();

	//return vector of processes sorted by pId
	static void GetProcesses(std::vector<PROCESSENTRY32>& processes, bool sort = false);
	
	static DWORD GetPorcessIdByName(const std::string& name);

	static HANDLE GetHandleByPid(const DWORD& pId);

	static HANDLE GetHandleByName(const std::string& name);

	static DWORD GetFileSize(const std::string& name);

	static void ReadDosHeader(const std::string& name, IMAGE_DOS_HEADER& dosHeader);

	static void ReadPEHeader(const std::string& name,  IMAGE_NT_HEADERS& peHeader);

	static void ReadSection(const std::string& name, IMAGE_SECTION_HEADER& sectionHeader, const int sectionNumber);

	//vector.size() == peHeader->FileHeader->NumberOfSections
	static void GetSections(const std::string& name, std::vector<_IMAGE_SECTION_HEADER>& v);

	static void GetSectionData(const std::string& name, const int sectionNumber);
};

