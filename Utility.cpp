#include "Utility.h"

Utility::Utility()
{
}

Utility::~Utility()
{
}

DWORD Utility::GetProcesses(std::vector<PROCESSENTRY32>& processes, bool sort) {
	PROCESSENTRY32 processEntry;

	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		CloseHandle(&hProcessSnap);
		return err;
	}

	// Set the size of the structure before using it.
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &processEntry)) {
		DWORD err = GetLastError();
		CloseHandle(&hProcessSnap);
		return err;
	}

	processes.clear();

	do {
		processes.push_back(processEntry);
	} while (Process32Next(hProcessSnap, &processEntry));

	CloseHandle(hProcessSnap);

	if (sort) {
		std::sort(processes.begin(), processes.end(), [](PROCESSENTRY32 r, PROCESSENTRY32 l) {
			return r.th32ProcessID < l.th32ProcessID;
			});
	}
	return 0;
}

DWORD Utility::GetPorcessIdByName(const std::string& name) {

	std::vector<PROCESSENTRY32> processes;
	if (Utility::GetProcesses(processes, false) == 0) {

		for (const auto& p : processes) {
			if (lstrcmpi(p.szExeFile, name.data()) == 0)
				return p.th32ProcessID;
		}
	}
	
	return -1;
}


