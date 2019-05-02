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

HANDLE Utility::GetHandleByPid(DWORD pId) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
	DWORD err = GetLastError();
	if (err) {
		std::cout << "GetHandleByPid error :" << err << std::endl;
	}
	return hProcess;
}

HANDLE Utility::GetHandleByName(const std::string& name) {
	DWORD pId = Utility::GetPorcessIdByName(name);
	HANDLE h = GetHandleByPid(pId);
	return h;
}

void Utility::EnableDebugPriv() {
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}

void Utility::ReadDosHeader(const std::string& name, PIMAGE_DOS_HEADER header) {
	std::ifstream file;
	file.open(name, std::ios_base::binary);

	if (!file.is_open())
		return;

	// get length of file
	file.seekg(0, std::ios::end);
	size_t fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<BYTE> data(sizeof(IMAGE_DOS_HEADER), 0);

	file.read(reinterpret_cast<char*>(&data[0]), sizeof(IMAGE_DOS_HEADER));

	if (fileSize >= sizeof(header))	{
		std::memcpy(header, &data[0], sizeof(header));
	}

	std::cout << header->e_lfanew;
}



