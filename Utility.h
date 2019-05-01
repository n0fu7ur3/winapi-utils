#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

class Utility
{
public:
	Utility();
	~Utility();

	//return vector of processes sorted by pId
	static DWORD GetProcesses(std::vector<PROCESSENTRY32>& processes, bool sort = false);
	
	static DWORD GetPorcessIdByName(const std::string& name);
};

