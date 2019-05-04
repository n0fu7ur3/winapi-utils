#include "Utility.h"

Utility::Utility() {

}

Utility::~Utility() {

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

DWORD Utility::GetFileSize(const std::string& name)
{
	std::ifstream file;
	file.open(name, std::ios_base::binary);

	if (!file.is_open())
		return 0;

	// get length of file
	file.seekg(0, std::ios::end);
	DWORD fileSize = file.tellg();
	file.seekg(0, std::ios::beg);
	return fileSize;
}

bool Utility::ReadDosHeader(const std::string& name, IMAGE_DOS_HEADER& dosHeader) {
	FILE* fp = fopen(name.data(), "rb");
	if (!fp)
		return false;

	DWORD fileSize = Utility::GetFileSize(name);
	if (fileSize == 0)
		return false;

	if (fileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
		return false;

	fseek(fp, 0, SEEK_SET);
	fread(&dosHeader, 1, sizeof(dosHeader), fp);

	//5A * 100 + 4D
	if (dosHeader.e_magic != 'M' + 'Z' * 256)
		return false;

	fclose(fp);
	return true;
}

bool Utility::ReadPEHeader(const std::string& name, IMAGE_NT_HEADERS& peHeader) {
	FILE* fp = fopen(name.data(), "rb");
	if (!fp)
		return false;

	_IMAGE_DOS_HEADER dosHeader{ 0 };
	Utility::ReadDosHeader(name, dosHeader);

	DWORD fileSize = Utility::GetFileSize(name);
	if (fileSize == 0)
		return false;

	if (!Utility::ReadDosHeader(name, dosHeader))
		return false;

	DWORD RawPointerToPeHeader = dosHeader.e_lfanew;
	if (fileSize <= RawPointerToPeHeader + sizeof(IMAGE_NT_HEADERS))
		return false;

	fseek(fp, RawPointerToPeHeader, SEEK_SET);
	fread(&peHeader.Signature, 1, sizeof(DWORD), fp);

	if (peHeader.Signature != 'P' + 'E' * 256)
		return false;

	fread(&peHeader.FileHeader, 1, sizeof(peHeader.FileHeader), fp);

	if (peHeader.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
		return false;

	int sectionCount = peHeader.FileHeader.NumberOfSections;
	if (sectionCount == 0) {
		printf("No section for this file.\n");
		fclose(fp);
		return false;
	}

	fclose(fp);
	return true;
}

bool Utility::ReadSection(const std::string& name, IMAGE_SECTION_HEADER& sectionHeader, const int sectionNumber) {
	FILE* fp = fopen(name.data(), "rb");
	if (!fp)
		return false;

	IMAGE_DOS_HEADER dosHeader{ 0 };
	Utility::ReadDosHeader(name, dosHeader);

	DWORD fileSize = Utility::GetFileSize(name);
	if (fileSize == 0)
		return false;

	IMAGE_NT_HEADERS peHeader{ 0 };
	Utility::ReadPEHeader(name, peHeader);
	
	if (fileSize <= dosHeader.e_lfanew +
		sizeof(IMAGE_NT_HEADERS) +
		peHeader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))
		return false;

	fseek(fp,
		dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) +
		(sectionNumber) * sizeof(IMAGE_SECTION_HEADER),
		SEEK_SET);
	fread(&sectionHeader, 1, sizeof(sectionHeader), fp);

	fclose(fp);
	return true;
}

bool Utility::GetSections(const std::string& name, std::vector<_IMAGE_SECTION_HEADER>& v) {
	v.clear();

	IMAGE_NT_HEADERS peHeader{ 0 };
	if (!Utility::ReadPEHeader(name, peHeader))
		return false;

	for (int i = 0; i < peHeader.FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER sectionHeader{ 0 };
		Utility::ReadSection(name, sectionHeader, i);
		v.push_back(sectionHeader);
	}

	return true;
}

bool Utility::GetSectionData(const std::string& name, const int sectionNumber) {
	FILE* fp = fopen(name.data(), "rb");
	if (!fp)
		return false;

	DWORD fileSize = Utility::GetFileSize(name);
	if (fileSize == 0)
		return false;

	IMAGE_SECTION_HEADER sectionHeader{ 0 };
	if (!Utility::ReadSection(name, sectionHeader, sectionNumber))
		return false;

	DWORD byteCount = sectionHeader.Misc.VirtualSize < sectionHeader.PointerToRawData ?
		sectionHeader.Misc.VirtualSize : sectionHeader.PointerToRawData;

	if (byteCount == 0)	{
		printf("No data to read for target section.\n");
		fclose(fp);
		return false;
	}
	else if (byteCount + sectionHeader.PointerToRawData > fileSize)	{
		printf("Bad section data.\n");
		fclose(fp);
		return false;
	}
	fseek(fp, sectionHeader.PointerToRawData, SEEK_SET);

	BYTE* pData = (BYTE*)malloc(byteCount);

	fread(pData, 1, byteCount, fp);
	
	fclose(fp);
	return true;
}

