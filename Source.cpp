#include "Utility.h"

void PrintProcesses()
{
	std::vector<PROCESSENTRY32> processes;
	if (Utility::GetProcesses(processes, true) == 0) {

		for (const auto& p : processes) {
			std::cout << "pId: " << p.th32ProcessID << " " << "Name: " << p.szExeFile << std::endl;
		}
	}
}

int main()
{
	Utility::EnableDebugPriv();

	PIMAGE_DOS_HEADER pHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));//  PIMAGE_DOS_HEADER;

	Utility::ReadDosHeader("D:\\Projects\\C_C++\\Repos\\winapi-utils\\Debug\\utility.exe", pHeader);

	PIMAGE_NT_HEADERS pPeHeader = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));

	Utility::ReadPEHeader("D:\\Projects\\C_C++\\Repos\\winapi-utils\\Debug\\utility.exe", pHeader->e_lfanew ,pPeHeader);


	free(pHeader);
	free(pPeHeader);
}