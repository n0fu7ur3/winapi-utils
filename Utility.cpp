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

void Utility::GetProcesses(std::vector<PROCESSENTRY32>& processes, bool sort) {
	PROCESSENTRY32 processEntry;

	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		CloseHandle(hProcessSnap);
		std::string err_str = "CreateToolhelp32Snapshot error: ";
		err_str += std::to_string(err);
		throw std::exception(err_str.c_str());
	}

	// Set the size of the structure before using it.
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &processEntry)) {
		DWORD err = GetLastError();
		CloseHandle(hProcessSnap);
		std::string err_str = "cant take information about the first process, error: ";
		err_str += std::to_string(err);
		throw std::exception(err_str.c_str());
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
}

DWORD Utility::GetPorcessIdByName(const std::string& name) {
	std::vector<PROCESSENTRY32> processes;
	try {
		Utility::GetProcesses(processes, false);
	}
	catch (std::exception& ex) {
		throw;
	}
	for (const auto& p : processes) {
		if (lstrcmpi(p.szExeFile, name.data()) == 0)
			return p.th32ProcessID;
	}
	throw std::exception("process not found");
}

HANDLE Utility::GetHandleByPid(const DWORD pId) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
	DWORD err = GetLastError();
	if (err) {
		CloseHandle(hProcess);
		std::string error = "Open process error: ";
		error += std::to_string(err);
		throw std::exception(error.c_str());
	}
	return hProcess;
}

HANDLE Utility::GetHandleByName(const std::string& name) {
	DWORD pId = 0;
	try {
		pId = Utility::GetPorcessIdByName(name);
		HANDLE h = GetHandleByPid(pId);
		return h;
	}
	catch (std::exception & ex) {
		throw;
	}	
}

DWORD Utility::GetFileSize(const std::string& name) {
	std::ifstream file;
	file.open(name, std::ios_base::binary);

	if (!file.is_open())
		throw std::exception("cant open file");

	// get length of file
	file.seekg(0, std::ios::end);
	DWORD fileSize = file.tellg();
	file.seekg(0, std::ios::beg);
	return fileSize;
}

void Utility::ReadDosHeader(const std::string& name, IMAGE_DOS_HEADER& dosHeader) {
	DWORD fileSize = 0;
	FILE* fp = fopen(name.data(), "rb");
	if (!fp)
		throw std::exception("cant open file");

	try {
		fileSize = Utility::GetFileSize(name);
	}
	catch (std::exception & ex) {
		throw;
	}

	if (fileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
		throw std::exception("bad file");

	fseek(fp, 0, SEEK_SET);
	fread(&dosHeader, 1, sizeof(dosHeader), fp);

	//5A * 100 + 4D
	if (dosHeader.e_magic != 'M' + 'Z' * 256)
		throw std::exception("e_magic != MZ");

	fclose(fp);
}

void Utility::ReadPEHeader(const std::string& name, IMAGE_NT_HEADERS& peHeader) {
	FILE* fp = fopen(name.data(), "rb");
	DWORD fileSize = 0;
	if (!fp)
		throw std::exception("cant open file");

	_IMAGE_DOS_HEADER dosHeader{ 0 };
	try {
		Utility::ReadDosHeader(name, dosHeader);
		fileSize = Utility::GetFileSize(name);
	}
	catch (std::exception & ex) {
		throw;
	}

	DWORD RawPointerToPeHeader = dosHeader.e_lfanew;
	if (fileSize <= RawPointerToPeHeader + sizeof(IMAGE_NT_HEADERS))
		throw std::exception("bad file");

	fseek(fp, RawPointerToPeHeader, SEEK_SET);
	fread(&peHeader.Signature, 1, sizeof(DWORD), fp);

	if (peHeader.Signature != 'P' + 'E' * 256)
		throw std::exception("PE signature != PE");

	fread(&peHeader.FileHeader, 1, sizeof(peHeader.FileHeader), fp);

	if (peHeader.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
		throw std::exception("bad SizeOfOptionalHeader");

	int sectionCount = peHeader.FileHeader.NumberOfSections;
	if (sectionCount == 0) {
		fclose(fp);
		throw std::exception("No section for this file");
	}

	fclose(fp);
}

void Utility::ReadSection(const std::string& name, IMAGE_SECTION_HEADER& sectionHeader, const int sectionNumber) {
	FILE* fp = fopen(name.data(), "rb");
	DWORD fileSize = 0;
	if (!fp)
		throw std::exception("cant open file");

	IMAGE_DOS_HEADER dosHeader{ 0 };
	IMAGE_NT_HEADERS peHeader{ 0 };
	try {
		Utility::ReadDosHeader(name, dosHeader);
		fileSize = Utility::GetFileSize(name);
		Utility::ReadPEHeader(name, peHeader);
	}
	catch (std::exception & ex) {
		throw;
	}

	if (fileSize <= dosHeader.e_lfanew +
		sizeof(IMAGE_NT_HEADERS) +
		peHeader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))
		throw std::exception("bad file");

	fseek(fp,
		dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) +
		(sectionNumber) * sizeof(IMAGE_SECTION_HEADER),
		SEEK_SET);
	fread(&sectionHeader, 1, sizeof(sectionHeader), fp);

	fclose(fp);
}

void Utility::GetSections(const std::string& name, std::vector<_IMAGE_SECTION_HEADER>& v) {
	v.clear();

	IMAGE_NT_HEADERS peHeader{ 0 };
	try {
		Utility::ReadPEHeader(name, peHeader);
	}
	catch (std::exception & ex) {
		throw;
	}

	for (int i = 0; i < peHeader.FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER sectionHeader{ 0 };
		Utility::ReadSection(name, sectionHeader, i);
		v.push_back(sectionHeader);
	}
}

void Utility::GetSectionData(const std::string& name, const int sectionNumber) {
	FILE* fp = fopen(name.data(), "rb");
	DWORD fileSize = 0;
	if (!fp)
		throw std::exception("cant open file");

	IMAGE_SECTION_HEADER sectionHeader{ 0 };
	try {
		fileSize = Utility::GetFileSize(name);
		Utility::ReadSection(name, sectionHeader, sectionNumber);
	}
	catch (std::exception & ex) {
		throw;
	}

	DWORD byteCount = sectionHeader.Misc.VirtualSize < sectionHeader.PointerToRawData ?
		sectionHeader.Misc.VirtualSize : sectionHeader.PointerToRawData;

	if (byteCount == 0)	{
		throw std::exception("No data to read for target section");
		fclose(fp);
	}
	else if (byteCount + sectionHeader.PointerToRawData > fileSize)	{
		throw std::exception("Bad section data");
		fclose(fp);
	}
	fseek(fp, sectionHeader.PointerToRawData, SEEK_SET);

	BYTE* pData = (BYTE*)malloc(byteCount);

	fread(pData, 1, byteCount, fp);
	
	fclose(fp);
}

