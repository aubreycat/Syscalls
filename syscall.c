#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <tlhelp32.h>
#include "syscall.h" // Include the new header file

// Function prototypes
void DumpExportedFunctions(void* libHandle, bool onlyNtFunctions, FILE* logFile);
void CheckIfFunctionHooked(const char* functionName, DWORD* functionAddress, bool onlyNtFunctions, FILE* logFile);
void ListLoadedModules(FILE* logFile);
void PrintBanner(FILE* logFile);

// List all loaded modules in the current process
void ListLoadedModules(FILE* logFile) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    SET_YELLOW_COLOR();
    printf("\nHere are the loaded modules:\n");
    fprintf(logFile, "\nHere are the loaded modules:\n");

    if (Module32First(hSnapshot, &moduleEntry)) {
        do {
            printf("%-50s 0x%016llX\n", moduleEntry.szExePath, (unsigned long long)moduleEntry.modBaseAddr);
            fprintf(logFile, "%-50s 0x%016llX\n", moduleEntry.szExePath, (unsigned long long)moduleEntry.modBaseAddr);
        } while (Module32Next(hSnapshot, &moduleEntry));
    }

    CloseHandle(hSnapshot);
    RESET_COLOR();
}

// Dump exported functions from a DLL and check if they're hooked
void DumpExportedFunctions(void* libHandle, bool onlyNtFunctions, FILE* logFile) {
    MY_IMAGE_DOS_HEADER* dosHeader = (MY_IMAGE_DOS_HEADER*)libHandle;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)libHandle + dosHeader->e_lfanew);
    MY_IMAGE_EXPORT_DIRECTORY* exportDir = (MY_IMAGE_EXPORT_DIRECTORY*)((BYTE*)libHandle + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameAddresses = (DWORD*)((BYTE*)libHandle + exportDir->AddressOfNames);

    SET_YELLOW_COLOR();
    printf("\nExported functions%s:\n\n", onlyNtFunctions ? " (NT functions only)" : "");
    fprintf(logFile, "\nExported functions%s:\n\n", onlyNtFunctions ? " (NT functions only)" : "");

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)libHandle + nameAddresses[i];
        FARPROC functionAddress = GetProcAddress((HMODULE)libHandle, functionName);
        CheckIfFunctionHooked(functionName, (DWORD*)functionAddress, onlyNtFunctions, logFile);
    }

    RESET_COLOR();
}

// Check if a function is hooked by examining its first opcode
void CheckIfFunctionHooked(const char* functionName, DWORD* functionAddress, bool onlyNtFunctions, FILE* logFile) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (onlyNtFunctions && strncmp(functionName, "Nt", 2) != 0) {
        return;
    }

    BYTE* opcode = (BYTE*)functionAddress;

    if (*opcode == 0xE9) {
        SET_RED_COLOR();
        printf("%s is hooked\n", functionName);
        fprintf(logFile, "%s is hooked at 0x%p\n", functionName, functionAddress);
        RESET_COLOR();
    } else {
        SET_ORANGE_COLOR();
        printf("%s\n", functionName);
        fprintf(logFile, "%s at 0x%p\n", functionName, functionAddress);
        RESET_COLOR();
    }
}

// Print a silly message (because why not?)
void PrintBanner(FILE* logFile) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SET_ORANGE_COLOR();
    printf("\nFinding Intercepted syscalls using C With Aubrey! ^-^\n");
    fprintf(logFile, "\nFinding Intercepted syscalls using C With Aubrey! ^-^\n");
    RESET_COLOR();
}

int main(int argc, char** argv) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FILE* logFile = fopen("hooks.txt", "w");

    if (argc < 2) {
        SET_RED_COLOR();
        fprintf(stderr, "Usage: %s <dll> [--all]\n", argv[0]);
        RESET_COLOR();
        fclose(logFile);
        return 1;
    }

    const char* dllPath = argv[1];
    HMODULE dllHandle = LoadLibraryA(dllPath);
    bool onlyNtFunctions = (argc == 2) || (argc > 2 && strcmp(argv[2], "--all") != 0);

    PrintBanner(logFile);

    SET_ORANGE_COLOR();
    printf("Loading %s...\n", dllPath);
    fprintf(logFile, "Loading %s...\n", dllPath);
    RESET_COLOR();
    if (dllHandle == NULL) {
        SET_RED_COLOR();
        fprintf(stderr, "Oops, couldn't load the DLL!\n");
        fprintf(logFile, "Oops, couldn't load the DLL!\n");
        RESET_COLOR();
        fclose(logFile);
        return 1;
    }

    ListLoadedModules(logFile);

    SET_YELLOW_COLOR();
    printf("\n____________________________________________\n");
    fprintf(logFile, "\n____________________________________________\n");
    RESET_COLOR();
    DumpExportedFunctions(dllHandle, onlyNtFunctions, logFile);
    SET_YELLOW_COLOR();
    printf("\n____________________________________________\n");
    fprintf(logFile, "\n____________________________________________\n");
    RESET_COLOR();

    FreeLibrary(dllHandle);
    fclose(logFile);

    SET_ORANGE_COLOR();
    printf("\nAll done! Check hooks.txt for more info :3\n");
    RESET_COLOR();

    return 0;
}