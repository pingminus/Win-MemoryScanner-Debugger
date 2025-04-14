#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <thread>
#include <mutex>
#include <conio.h>

std::mutex addrMutex;
const SIZE_T BUFFER_SIZE = 4096;

enum class ScanType {
    INT,
    FLOAT,
    SHORT
};

std::string ScanTypeName(ScanType type) {
    switch (type) {
    case ScanType::INT: return "int";
    case ScanType::FLOAT: return "float";
    case ScanType::SHORT: return "short";
    default: return "unknown";
    }
}

void ScanMemoryChunk(HANDLE hProcess, uintptr_t start, uintptr_t end, ScanType type, void* targetValue, std::unordered_set<uintptr_t>& foundAddresses) {
    std::vector<BYTE> buffer(BUFFER_SIZE);
    SIZE_T bytesRead;

    for (uintptr_t addr = start; addr < end; addr += BUFFER_SIZE) {
        if (ReadProcessMemory(hProcess, (LPCVOID)addr, buffer.data(), BUFFER_SIZE, &bytesRead)) {
            for (SIZE_T i = 0; i < bytesRead - sizeof(int); i++) {
                bool match = false;

                switch (type) {
                case ScanType::INT: {
                    int val;
                    memcpy(&val, &buffer[i], sizeof(int));
                    match = (val == *(int*)targetValue);
                    break;
                }
                case ScanType::FLOAT: {
                    float val;
                    memcpy(&val, &buffer[i], sizeof(float));
                    match = (val == *(float*)targetValue);
                    break;
                }
                case ScanType::SHORT: {
                    short val;
                    memcpy(&val, &buffer[i], sizeof(short));
                    match = (val == *(short*)targetValue);
                    break;
                }
                }

                if (match) {
                    std::lock_guard<std::mutex> lock(addrMutex);
                    foundAddresses.insert(addr + i);
                    std::cout << "Found at: 0x" << std::hex << addr + i << std::endl;
                }
            }
        }
    }
}

void ScanProcess(DWORD pid, ScanType type, void* targetValue, std::unordered_set<uintptr_t>& foundAddresses) {
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
            threads.emplace_back(ScanMemoryChunk, hProcess, (uintptr_t)mbi.BaseAddress, (uintptr_t)mbi.BaseAddress + mbi.RegionSize, type, targetValue, std::ref(foundAddresses));
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    for (auto& t : threads) t.join();
    CloseHandle(hProcess);
}

std::unordered_set<uintptr_t> CheckPreviousAddresses(DWORD pid, const std::unordered_set<uintptr_t>& addresses, ScanType type, void* targetValue) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process!" << std::endl;
        return {};
    }

    SIZE_T bytesRead;
    std::unordered_set<uintptr_t> newFound;

    for (const auto& addr : addresses) {
        bool match = false;

        switch (type) {
        case ScanType::INT: {
            int val;
            if (ReadProcessMemory(hProcess, (LPCVOID)addr, &val, sizeof(int), &bytesRead)) {
                if (val == *(int*)targetValue) {
                    std::cout << "0x" << std::hex << addr << " holds: " << std::dec << val << " (match)\n";
                    match = true;
                }
            }
            break;
        }
        case ScanType::FLOAT: {
            float val;
            if (ReadProcessMemory(hProcess, (LPCVOID)addr, &val, sizeof(float), &bytesRead)) {
                if (val == *(float*)targetValue) {
                    std::cout << "0x" << std::hex << addr << " holds: " << std::dec << val << " (match)\n";
                    match = true;
                }
            }
            break;
        }
        case ScanType::SHORT: {
            short val;
            if (ReadProcessMemory(hProcess, (LPCVOID)addr, &val, sizeof(short), &bytesRead)) {
                if (val == *(short*)targetValue) {
                    std::cout << "0x" << std::hex << addr << " holds: " << std::dec << val << " (match)\n";
                    match = true;
                }
            }
            break;
        }
        }

        if (match)
            newFound.insert(addr);
    }

    CloseHandle(hProcess);
    return newFound;
}

int main() {
    while (true) {
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

        std::cout << "\nInput index of process to scan: ";
        int input;
        std::cin >> input;
        if (processMap.find(input) == processMap.end()) return 0;

        DWORD pid = processMap[input].first;

        std::cout << "Select value type to scan:\n[1] int\n[2] float\n[3] short\n> ";
        int typeChoice;
        std::cin >> typeChoice;

        ScanType scanType = ScanType::INT;
        if (typeChoice == 2) scanType = ScanType::FLOAT;
        else if (typeChoice == 3) scanType = ScanType::SHORT;

        void* target = nullptr;
        int ival; float fval; short sval;

        std::cout << "Enter initial value: ";
        switch (scanType) {
        case ScanType::INT:
            std::cin >> ival; target = &ival; break;
        case ScanType::FLOAT:
            std::cin >> fval; target = &fval; break;
        case ScanType::SHORT:
            std::cin >> sval; target = &sval; break;
        }

        std::unordered_set<uintptr_t> foundAddresses;
        ScanProcess(pid, scanType, target, foundAddresses);
        std::cout << "Initial scan found " << foundAddresses.size() << " addresses.\n";

        char again;
        do {
            std::cout << "\nEnter new value to filter previous addresses: ";
            switch (scanType) {
            case ScanType::INT:
                std::cin >> ival; target = &ival; break;
            case ScanType::FLOAT:
                std::cin >> fval; target = &fval; break;
            case ScanType::SHORT:
                std::cin >> sval; target = &sval; break;
            }

            foundAddresses = CheckPreviousAddresses(pid, foundAddresses, scanType, target);
            std::cout << "Remaining matching addresses: " << foundAddresses.size() << "\n";
            std::cout << "Check again? [Y/N]: ";
            std::cin >> again;

        } while (again == 'Y' || again == 'y');
    }

    return 0;
}

