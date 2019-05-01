#include "Utility.h"


int main()
{
	std::vector<PROCESSENTRY32> processes;
	if (Utility::GetProcesses(processes, true) == 0) {
		
		for (const auto& p : processes) {
			std::cout << "pId: " <<p.th32ProcessID << " " << "Name: " << p.szExeFile << std::endl;
		}
		//std::cout << Utility::GetPorcessIdByName("Telegram.exe");
	}

	//HHOOK hHook = SetWindowsHookEx();
}