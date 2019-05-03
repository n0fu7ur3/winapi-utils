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

HANDLE Utility::GetHandleByPid(const DWORD pId) {
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

void Utility::ReadDosHeader(const std::string& name, IMAGE_DOS_HEADER* pDosHeader) {
	std::ifstream file;
	file.open(name, std::ios_base::binary);

	if (!file.is_open())
		return;

	std::vector<BYTE> data(sizeof(IMAGE_DOS_HEADER), 0);

	//char* buf = new char[sizeof(IMAGE_DOS_HEADER)];

	file.read(reinterpret_cast<char*>(&data[0]), sizeof(IMAGE_DOS_HEADER));
	//file.read(buf, sizeof(IMAGE_DOS_HEADER));

	std::memcpy(pDosHeader, &data[0], sizeof(IMAGE_DOS_HEADER));
	//std::memcpy(pDosHeader, buf, sizeof(IMAGE_DOS_HEADER));

	file.close();
}

void Utility::ReadPEHeader(const std::string& name, const LONG addr, PIMAGE_NT_HEADERS pPeHeader) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	ReadDosHeader(name, pDosHeader);
	size_t peHeaderOffset = pDosHeader->e_lfanew;

	std::ifstream file;
	file.open(name, std::ios_base::binary);

	if (!file.is_open())
		return;

	std::vector<BYTE> data(sizeof(IMAGE_NT_HEADERS), 0);

	file.seekg(peHeaderOffset);
	file.read(reinterpret_cast<char*>(&data[0]), sizeof(IMAGE_NT_HEADERS));

	std::memcpy(pPeHeader, &data[0], sizeof(IMAGE_NT_HEADERS));

	file.close();
}

int Utility::GetFileSize(const std::string& name)
{
	std::ifstream file;
	file.open(name, std::ios_base::binary);

	if (!file.is_open())
		return 0;

	// get length of file
	file.seekg(0, std::ios::end);
	size_t fileSize = file.tellg();
	file.seekg(0, std::ios::beg);
	return fileSize;
}



