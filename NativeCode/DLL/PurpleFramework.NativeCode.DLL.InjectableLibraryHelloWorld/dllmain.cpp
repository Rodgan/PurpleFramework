#include <Windows.h>
#include <stdio.h>

void Payload() {
	DWORD processId =  GetCurrentProcessId();

	MessageBoxA(0, "DLL successfully injected. Current process ID: " + processId, "DLL Injection", MB_OK);

	const char* path = "C:\\Test\\dllinjection.txt";

	FILE* fp = fopen(path, "w");
	fprintf(fp, "It works!\n");
	fclose(fp);
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		Payload();
		break;
	}

	return 1;
}