#include "Utility.h"

void PrintProcesses() {
	std::vector<PROCESSENTRY32> processes;
	try {
		Utility::GetProcesses(processes, true);
	}
	catch(DWORD err) {
		std::cout << "error: " << err << std::endl;
	}
	for (const auto& p : processes) {
		std::cout << "pId: " << p.th32ProcessID << " " << "Name: " << p.szExeFile << std::endl;
	}
}

void PrintSections(std::string& filePath) {
	IMAGE_NT_HEADERS peHeader{ 0 };
	Utility::ReadPEHeader(filePath, peHeader);

	for (int i = 0; i < peHeader.FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER sectionHeader{ 0 };
		Utility::ReadSection(filePath, sectionHeader, i);
		std::cout << sectionHeader.Name << std::endl;
	}
}

int main()
{
	Utility::EnableDebugPriv();

	std::string filePath = "D:\\Projects\\C_C++\\Repos\\winapi-utils\\Debug\\utility.exe";

	try {
		IMAGE_DOS_HEADER dosHeader{ 0 };
		Utility::ReadDosHeader(filePath, dosHeader);

		IMAGE_NT_HEADERS peHeader{ 0 };
		Utility::ReadPEHeader(filePath, peHeader);

		std::vector<_IMAGE_SECTION_HEADER> v(0);
		Utility::GetSections(filePath, v);
	}
	catch (std::exception & ex) {
		std::cout << ex.what();
	}

	HANDLE h = Utility::GetHandleByName("telegram.exe");
	HandleRAII h1(h);
	std::cout << h;
}