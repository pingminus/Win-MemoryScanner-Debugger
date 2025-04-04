#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <thread>
#include <mutex>
#include <conio.h>

std::mutex addrMutex;  // Protect shared memory
const SIZE_T BUFFER_SIZE = 4096; // Read in 4KB chunks for efficiency

void ScanMemoryChunk(HANDLE hProcess, uintptr_t start, uintptr_t end, int targetValue, std::unordered_set<uintptr_t>& foundAddresses) {
    std::vector<BYTE> buffer(BUFFER_SIZE);
    SIZE_T bytesRead;

    for (uintptr_t addr = start; addr < end; addr += BUFFER_SIZE) {
        if (ReadProcessMemory(hProcess, (LPCVOID)addr, buffer.data(), BUFFER_SIZE, &bytesRead)) {
            for (SIZE_T i = 0; i < bytesRead - sizeof(int); i++) {
                int* valuePtr = reinterpret_cast<int*>(&buffer[i]);
                if (*valuePtr == targetValue) {
                    std::lock_guard<std::mutex> lock(addrMutex);
                    foundAddresses.insert(addr + i);
                    std::cout << "Found value at: " << std::hex << addr + i << std::endl;
                }
            }
        }
    }
}

void ScanProcess(DWORD pid, int targetValue, std::unordered_set<uintptr_t>& foundAddresses) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process!" << std::endl;
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    std::vector<std::thread> threads;

    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD)) {
            threads.emplace_back(ScanMemoryChunk, hProcess, (uintptr_t)mbi.BaseAddress, (uintptr_t)mbi.BaseAddress + mbi.RegionSize, targetValue, std::ref(foundAddresses));
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    for (auto& t : threads) t.join(); // Wait for all threads to finish

    CloseHandle(hProcess);
}

std::unordered_set<uintptr_t> CheckPreviousAddresses(DWORD pid, const std::unordered_set<uintptr_t>& addresses, int newTargetValue) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process!" << std::endl;
        return {};
    }

    SIZE_T bytesRead;
    int buffer;
    std::unordered_set<uintptr_t> newFoundAddresses;

    for (const auto& addr : addresses) {
        if (ReadProcessMemory(hProcess, (LPCVOID)addr, &buffer, sizeof(buffer), &bytesRead)) {
            if (buffer == newTargetValue) {
                std::cout << "Address " << std::hex << addr << " now holds the new target value!" << std::endl;
                newFoundAddresses.insert(addr);  // Add to newFoundAddresses if the value matches
            }
        }
    }

    CloseHandle(hProcess);
    return newFoundAddresses;
}

int main() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    std::unordered_map<int, std::pair<DWORD, std::wstring>> processMap;
    int index = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            std::wcout << index << ". PID: " << pe.th32ProcessID << L": " << pe.szExeFile << std::endl;
            processMap[index] = { pe.th32ProcessID, pe.szExeFile };
            index++;
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    std::cout << "\nInput Index of process you want to scan: ";
    int input;
    std::cin >> input;

    if (processMap.find(input) == processMap.end()) return 0;

    std::wcout << "\nScan this Process?: Pname: " << processMap[input].second << " PID: " << processMap[input].first << std::endl;
    std::cout << "[Y] or [N]: ";
    char c;
    std::cin >> c;
    if (c == 'N') return 0;

    std::cout << "Enter value to search for: ";
    int targetValue;
    std::cin >> targetValue;

    std::unordered_set<uintptr_t> foundAddresses;
    ScanProcess(processMap[input].first, targetValue, foundAddresses);

    std::cout << "Do you want to check previous addresses for new target value again?" << std::endl;
    std::cout << "[Y] or [N]: ";
    char checkAgain;
    std::cin >> checkAgain;

    while (checkAgain == 'Y') {
        // Create a new map before checking
        std::cout << "Enter new value to search for in the previously found addresses: ";
        int newTargetValue;
        std::cin >> newTargetValue;

        // Get the new set of addresses matching the new target value
        foundAddresses = CheckPreviousAddresses(processMap[input].first, foundAddresses, newTargetValue);

        std::cout << "Do you want to check previous addresses for new target value again?" << std::endl;
        std::cout << "[Y] or [N]: ";
        std::cin >> checkAgain;
    }

    return 0;
}
