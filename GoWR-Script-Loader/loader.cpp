#include "pch.h"
#include <windows.h>
#include <psapi.h>
#include <detours.h>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <set>
#include <spdlog/spdlog.h>
#include <mini/ini.h>
#pragma comment(lib, "detours.lib")
typedef uint64_t QWORD;
bool DUMP_LUA = false;
bool DUMP_VISUAL_SCRIPT = false;
bool LOAD_LUA = true;
bool LOAD_VISUAL_SCRIPT = true;
QWORD baseAddress;
QWORD hookRetAddress;
std::set<std::string> nameSet;

typedef int(__fastcall* Lua_Load)(QWORD L, QWORD reader, QWORD data, const char* chunkname, const char* mode);
Lua_Load originalLoadLuaFunctionAddr;
typedef QWORD(__fastcall* Visual_Script_Load)(QWORD rcx, QWORD rdx, QWORD r8, QWORD r9);
Visual_Script_Load originalLoadVisualScriptFunctionAddr;

int __stdcall lua_loadR(QWORD L, QWORD reader, QWORD data, const char* chunkname, const char* mode) {
    int dataSize = *(int*)data;
    std::string fileNameStr(chunkname);
    fileNameStr = fileNameStr.substr(4);
    std::string dumpFileName = "dump\\" + fileNameStr;
    std::string modFileName = "mod\\" + fileNameStr;
    if (!nameSet.contains(chunkname)) {
        nameSet.insert(chunkname);
        if (DUMP_LUA) {
            spdlog::info("Dump file " + dumpFileName);
            std::filesystem::create_directories(dumpFileName.substr(0, dumpFileName.rfind("\\")));
            std::ofstream outFile(dumpFileName, std::ios::binary);
            outFile.write((const char*)*(QWORD*)(data + 0x8), dataSize);
            outFile.close();
        }
    }
    if (LOAD_LUA) {
        std::ifstream file(modFileName, std::ios::binary | std::ios::ate);
        if (file.good()) {
            spdlog::info("replace with modded file " + modFileName);
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            char* buffer = new char[size];
            QWORD chunckInfo[2] = { 0,0 };
            int* sizePtr = (int*)&chunckInfo[0];
            *sizePtr = size;
            chunckInfo[1] = (QWORD)&buffer[0];
            file.read(buffer, size);
            int result = originalLoadLuaFunctionAddr(L, reader, (QWORD)&chunckInfo[0], chunkname, NULL);
            delete[]buffer;
            file.close();
            return result;
        }
    }
    return originalLoadLuaFunctionAddr(L, reader, data, chunkname, NULL);
}

QWORD __stdcall visual_script_loadR(QWORD rcx, QWORD rdx, QWORD r8, QWORD r9) {
    if (*(int*)r9 == 0x16) {
        char* name = (char*)(r9 + 0x238);
        int dataSize = 0x1f0 + 8 * (*(int*)(r9 + 0x1e8)) + (*(int*)(r9 + 0x1f0));

        std::string fileNameStr(name);
        std::string dumpFileName = "dump\\int9\\" + fileNameStr;
        std::string modFileName = "mod\\int9\\" + fileNameStr;
        if (!nameSet.contains(name)) {
            nameSet.insert(name);

            if (DUMP_VISUAL_SCRIPT) {
                spdlog::info("Dump file " + fileNameStr);
                std::filesystem::create_directories(dumpFileName.substr(0, dumpFileName.rfind("\\")));
                std::ofstream outFile(dumpFileName, std::ios::binary);
                outFile.write((const char*)(r9), dataSize);
                outFile.close();
            }
        }
        if (LOAD_VISUAL_SCRIPT) {
            std::ifstream file(modFileName, std::ios::binary);
            if (file.good()) {
                spdlog::info("replace with modded file " + modFileName);
                file.read((char*)r9, dataSize);
                file.close();
            }
        }
    }

    return originalLoadVisualScriptFunctionAddr(rcx, rdx, r8, r9);
}

bool get_module_bounds(const std::wstring name, uintptr_t* start, uintptr_t* end)
{
	const auto module = GetModuleHandle(name.c_str());
	if (module == nullptr)
		return false;

	MODULEINFO info;
	GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info));
	*start = (uintptr_t)(info.lpBaseOfDll);
	*end = *start + info.SizeOfImage;
	return true;
}

// Scan for a byte pattern with a mask in the form of "xxx???xxx".
uintptr_t sigscan(const std::wstring name, const char* sig, const char* mask)
{
	uintptr_t start, end;
	if (!get_module_bounds(name, &start, &end))
		throw std::runtime_error("Module not loaded");

	const auto last_scan = end - strlen(mask) + 1;

	for (auto addr = start; addr < last_scan; addr++) {
		for (size_t i = 0;; i++) {
			if (mask[i] == '\0')
				return addr;
			if (mask[i] != '?' && sig[i] != *(char*)(addr + i))
				break;
		}
	}

	return NULL;
}

void hookLuaLoadfunction() {
    baseAddress = (uintptr_t)GetModuleHandle(L"GoWR.exe");
    originalLoadLuaFunctionAddr = (Lua_Load)(sigscan(
        L"GoWR.exe",
        "\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xec\x50\x49\x8b\xd9\x48\x8b\xf9",
        "xxxxxxxxxxxxxxxxxxxxx"));
    originalLoadVisualScriptFunctionAddr = (Visual_Script_Load)(sigscan(
        L"GoWR.exe",
        "\x40\x55\x53\x56\x57\x41\x54\x41\x56\x41\x57\x48\x8d\xac\x24\xc0",
        "xxxxxxxxxxxxxxxx"));
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(LPVOID&)originalLoadLuaFunctionAddr, (PBYTE)lua_loadR);
    DetourTransactionCommit();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(LPVOID&)originalLoadVisualScriptFunctionAddr, (PBYTE)visual_script_loadR);
    DetourTransactionCommit();
}
DWORD WINAPI loaderInit(LPVOID lpThreadParameter)
{
    spdlog::info("Script Loader Init");
    mINI::INIFile file("GOWR-Script-Loader.ini");
    mINI::INIStructure ini;
    if (file.read(ini)) {
        if (ini.has("Dump")) {
            if (ini["Dump"].has("Lua")) {
                DUMP_LUA = ini["Dump"]["Lua"] == "1";
            }
            if (ini["Dump"].has("VisualScript")) {
                DUMP_VISUAL_SCRIPT = ini["Dump"]["VisualScript"] == "1";
            }
        }
        if (ini.has("Load")) {
            if (ini["Load"].has("Lua")) {
                LOAD_LUA = ini["Load"]["Lua"] == "1";
            }
            if (ini["Load"].has("VisualScript")) {
                LOAD_VISUAL_SCRIPT = ini["Load"]["VisualScript"] == "1";
            }
        }
    }
    else {
        ini["Dump"]["Lua"] = "0";
        ini["Dump"]["VisualScript"] = "0";
        ini["Load"]["Lua"] = "1";
        ini["Load"]["VisualScript"] = "1";
        file.generate(ini);
    }
    hookLuaLoadfunction();
    spdlog::info("Script Loader Init Finished");
    return 0;
}