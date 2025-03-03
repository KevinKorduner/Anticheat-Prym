// PRYM.cpp
// Si usas precompiled headers, incluye "pch.h". Si no, elimina esta línea.
#include "pch.h"
#include <windows.h>
#include <TlHelp32.h>
#include <wincrypt.h>
#include <oleauto.h>         // Para BSTR y SysAllocStringLen
#include <string>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <vector>
#include <exception>

// Declaración anticipada para WriteLog para evitar errores de compilación.
void WriteLog(const std::string& logContent);

// Variable global para guardar el handle de la DLL
HMODULE g_hModule = NULL;

// Variable global para mostrar logs. Por defecto en true para desarrollo; en producción se establecerá a false.
bool g_ShowLogs = true;

// Caché global para evitar recalcular hashes (clave: path del archivo, valor: hash SHA256)
std::unordered_map<std::string, std::string> g_FileHashCache;
std::mutex g_CacheMutex;

// Mutex para la escritura sincronizada de logs
std::mutex g_LogMutex;

// Lista de hashes SHA256 (en formato hexadecimal) de los cheats.
// Reemplaza estos ejemplos con tus hashes reales.
const char* g_CheatHashes[] = {
    "a53e1e6efbe80ds3864f870067b78be11c989986904136761d932a896d64bcdd", // Cheat engine
    "a6ee6610d83bbe55e9dacdff2005950d69fc2d3c54e28467b82c148e274d90da" // Autoclicker
};
const int g_NumCheatHashes = sizeof(g_CheatHashes) / sizeof(g_CheatHashes[0]);

// Calcula el hash SHA256 de un archivo dado su path, usando caché para evitar recálculos.
bool ComputeFileSHA256(const char* filePath, std::string& outHash)
{
    try
    {
        {
            // Verifica en la caché si ya se calculó el hash para este archivo
            std::lock_guard<std::mutex> lock(g_CacheMutex);
            auto it = g_FileHashCache.find(filePath);
            if (it != g_FileHashCache.end())
            {
                outHash = it->second;
                return true;
            }
        }

        bool result = false;
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE buffer[4096];
        DWORD bytesRead = 0;
        BYTE hash[32] = { 0 }; // SHA256 produce 32 bytes.
        DWORD hashSize = sizeof(hash);

        if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            {
                while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL))
                {
                    if (bytesRead == 0)
                        break;
                    if (!CryptHashData(hHash, buffer, bytesRead, 0))
                        goto cleanup;
                }
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
                {
                    char hexStr[65] = { 0 };
                    for (DWORD i = 0; i < hashSize; i++)
                    {
                        sprintf_s(hexStr + i * 2, 65 - i * 2, "%02x", hash[i]);
                    }
                    outHash = std::string(hexStr);
                    result = true;
                }
            }
        }

    cleanup:
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);

        // Guarda en la caché si se obtuvo el hash correctamente
        if (result)
        {
            std::lock_guard<std::mutex> lock(g_CacheMutex);
            g_FileHashCache[filePath] = outHash;
        }
        return result;
    }
    catch (const std::exception& ex)
    {
        if (g_ShowLogs)
        {
            std::ostringstream oss;
            oss << "ComputeFileSHA256 error (" << filePath << "): " << ex.what() << "\n";
            WriteLog(oss.str());
        }
        return false;
    }
    catch (...)
    {
        if (g_ShowLogs)
        {
            std::ostringstream oss;
            oss << "ComputeFileSHA256 unknown error (" << filePath << ")\n";
            WriteLog(oss.str());
        }
        return false;
    }
}

// Recorre los módulos de un proceso y verifica si alguno coincide con los hashes.
// Si se detecta un hash de cheat, se termina el proceso de forma inmediata.
void ScanProcessModules(DWORD processID, std::ostringstream& oss)
{
    try
    {
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
        if (hModuleSnap == INVALID_HANDLE_VALUE)
            return;

        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(hModuleSnap, &me32))
        {
            CloseHandle(hModuleSnap);
            return;
        }

        bool cheatDetected = false;
        do
        {
#ifdef UNICODE
            int sizeNeeded = WideCharToMultiByte(CP_ACP, 0, me32.szExePath, -1, NULL, 0, NULL, NULL);
            std::string modulePath(sizeNeeded, 0);
            WideCharToMultiByte(CP_ACP, 0, me32.szExePath, -1, &modulePath[0], sizeNeeded, NULL, NULL);
#else
            std::string modulePath = me32.szExePath;
#endif
            std::string fileHash;
            if (ComputeFileSHA256(modulePath.c_str(), fileHash))
            {
                for (int i = 0; i < g_NumCheatHashes; i++)
                {
                    if (fileHash == g_CheatHashes[i])
                    {
                        // Obtiene fecha y hora actual
                        SYSTEMTIME st;
                        GetLocalTime(&st);
#ifdef UNICODE
                        int modSize = WideCharToMultiByte(CP_ACP, 0, me32.szModule, -1, NULL, 0, NULL, NULL);
                        std::string modName(modSize, 0);
                        WideCharToMultiByte(CP_ACP, 0, me32.szModule, -1, &modName[0], modSize, NULL, NULL);
                        oss << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
                            << st.wHour << ":" << st.wMinute << ":" << st.wSecond
                            << " - Proceso ID " << processID << " - Módulo detectado: "
                            << modName << " con hash: " << fileHash;
#else
                        oss << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
                            << st.wHour << ":" << st.wMinute << ":" << st.wSecond
                            << " - Proceso ID " << processID << " - Módulo detectado: "
                            << me32.szModule << " con hash: " << fileHash;
#endif
                        // Termina el proceso asociado al cheat de forma inmediata
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
                        if (hProc)
                        {
                            TerminateProcess(hProc, 1);
                            CloseHandle(hProc);
                            oss << " -> Proceso terminado.\n";
                        }
                        else
                        {
                            oss << " -> Error al terminar el proceso.\n";
                        }
                        cheatDetected = true;
                        break;
                    }
                }
            }
            if (cheatDetected)
                break;
        } while (Module32Next(hModuleSnap, &me32));
        CloseHandle(hModuleSnap);
    }
    catch (const std::exception& ex)
    {
        if (g_ShowLogs)
        {
            std::ostringstream errorOss;
            errorOss << "ScanProcessModules error en PID " << processID << ": " << ex.what() << "\n";
            oss << errorOss.str();
        }
    }
    catch (...)
    {
        if (g_ShowLogs)
        {
            std::ostringstream errorOss;
            errorOss << "ScanProcessModules unknown error en PID " << processID << "\n";
            oss << errorOss.str();
        }
    }
}

// Recorre todos los procesos en el sistema de forma paralela.
// Se lanza un hilo por cada proceso y se sincroniza el volcado de logs.
std::string ScanAllProcesses()
{
    try
    {
        std::ostringstream globalOss;
        std::vector<DWORD> processIDs;

        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            globalOss << "Error al crear snapshot de procesos.\n";
            return globalOss.str();
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &pe32))
        {
            do
            {
                processIDs.push_back(pe32.th32ProcessID);
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);

        std::vector<std::thread> threads;
        for (auto pid : processIDs)
        {
            threads.push_back(std::thread([pid, &globalOss]()
                {
                    std::ostringstream localOss;
                    ScanProcessModules(pid, localOss);
                    {
                        std::lock_guard<std::mutex> lock(g_LogMutex);
                        globalOss << localOss.str();
                    }
                }));
        }

        // Espera a que todos los hilos terminen
        for (auto& t : threads)
        {
            t.join();
        }
        return globalOss.str();
    }
    catch (const std::exception& ex)
    {
        if (g_ShowLogs)
        {
            std::ostringstream errorOss;
            errorOss << "ScanAllProcesses error: " << ex.what() << "\n";
            return errorOss.str();
        }
        return "";
    }
    catch (...)
    {
        if (g_ShowLogs)
        {
            return "ScanAllProcesses unknown error\n";
        }
        return "";
    }
}

// Devuelve el directorio donde reside la DLL.
std::string GetModuleDirectory()
{
    try
    {
#ifdef UNICODE
        wchar_t wpath[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(g_hModule, wpath, MAX_PATH))
        {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, NULL, 0, NULL, NULL);
            std::string path(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, wpath, -1, &path[0], size_needed, NULL, NULL);
            size_t pos = path.find_last_of("\\/");
            if (pos != std::string::npos)
                return path.substr(0, pos + 1);
        }
#else
        char path[MAX_PATH] = { 0 };
        if (GetModuleFileNameA(g_hModule, path, MAX_PATH))
        {
            std::string fullPath(path);
            size_t pos = fullPath.find_last_of("\\/");
            if (pos != std::string::npos)
                return fullPath.substr(0, pos + 1);
        }
#endif
        return "";
    }
    catch (const std::exception& ex)
    {
        if (g_ShowLogs)
        {
            std::ostringstream errorOss;
            errorOss << "GetModuleDirectory error: " << ex.what() << "\n";
            WriteLog(errorOss.str());
        }
        return "";
    }
    catch (...)
    {
        if (g_ShowLogs)
        {
            WriteLog("GetModuleDirectory unknown error\n");
        }
        return "";
    }
}

// Escribe logs en el archivo "logs.txt" en el mismo directorio que la DLL.
void WriteLog(const std::string& logContent)
{
    try
    {
        std::string directory = GetModuleDirectory();
        std::string logPath = directory + "logs.txt";
        std::ofstream ofs(logPath, std::ios::app);
        if (ofs)
        {
            ofs << logContent;
            ofs.close();
        }
    }
    catch (...)
    {
        // Se suprime cualquier error en la escritura de logs para no levantar sospechas.
    }
}

// Convierte un std::string a BSTR.
BSTR StringToBSTR(const std::string& str)
{
    try
    {
        int wslen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.length(), NULL, 0);
        BSTR bstr = SysAllocStringLen(NULL, wslen);
        MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.length(), bstr, wslen);
        return bstr;
    }
    catch (...)
    {
        return SysAllocString(L"");
    }
}

/// <summary>
/// Función que se ejecuta en un hilo paralelo para realizar el escaneo.
/// Al finalizar, muestra un MessageBox con el resultado final (sólo en modo desarrollo).
/// </summary>
DWORD WINAPI ScanThreadProc(LPVOID lpParameter)
{
    try
    {
        BOOL MostrarLogs = *(BOOL*)lpParameter;
        delete (BOOL*)lpParameter; // Libera la memoria

        // Actualiza la variable global según el parámetro recibido
        g_ShowLogs = (MostrarLogs != FALSE);

        ULONGLONG start = GetTickCount64();
        std::string scanResults = ScanAllProcesses();
        ULONGLONG end = GetTickCount64();
        ULONGLONG duration = end - start;

        std::ostringstream oss;
        oss << "Tiempo de escaneo: " << duration << " ms\n";
        oss << scanResults;
        std::string resultStr = oss.str();

        if (g_ShowLogs)
            WriteLog(resultStr);

        // Prepara el mensaje para mostrar en el MessageBox:
        std::string msg;
        if (scanResults.empty())
        {
            msg = "No se detectaron hashes";
        }
        else
        {
            msg = resultStr;
        }

        // Solo se muestra el MessageBox si los logs están habilitados (modo desarrollo)
        if (g_ShowLogs)
            MessageBoxA(NULL, msg.c_str(), "Estado del Scan", MB_ICONINFORMATION);

        return 0;
    }
    catch (const std::exception& ex)
    {
        if (g_ShowLogs)
        {
            std::ostringstream errorOss;
            errorOss << "ScanThreadProc error: " << ex.what() << "\n";
            WriteLog(errorOss.str());
        }
        return 1;
    }
    catch (...)
    {
        if (g_ShowLogs)
        {
            WriteLog("ScanThreadProc unknown error\n");
        }
        return 1;
    }
}

/// <summary>
/// Función exportada para iniciar el escaneo.
/// Parámetro: MostrarLogs (TRUE para escribir logs y mostrar MessageBox; FALSE para modo sigiloso)
/// Se lanza en un hilo paralelo para que VB6 no se trabe.
/// Retorna: BSTR con el mensaje "Scan iniciado en paralelo".
/// </summary>
extern "C" __declspec(dllexport) BSTR __stdcall RealizarScan(BOOL MostrarLogs)
{
    try
    {
        // Se reserva memoria para pasar el parámetro al hilo
        BOOL* pMostrarLogs = new BOOL(MostrarLogs);
        HANDLE hThread = CreateThread(NULL, 0, ScanThreadProc, pMostrarLogs, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread); // No se espera al hilo, se libera el handle
        }
        std::string msg = "Scan iniciado en paralelo";
        return StringToBSTR(msg);
    }
    catch (...)
    {
        return SysAllocString(L"");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        g_hModule = hModule;
    return TRUE;
}
