#include <windows.h>
#include <credentialprovider.h>
#include "credentialprovider.h"

// Global variables
HINSTANCE g_hInst = NULL;
long g_cDllRef = 0;

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hInst = hModule;
        DisableThreadLibraryCalls(hModule);
        break;
        
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// DllGetClassObject - Required for COM
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (IsEqualCLSID(rclsid, CLSID_GEEKSProvider))
    {
        return CreateGEEKSProvider(riid, ppv);
    }
    
    return CLASS_E_CLASSNOTAVAILABLE;
}

// DllCanUnloadNow - Required for COM
STDAPI DllCanUnloadNow()
{
    return (g_cDllRef == 0) ? S_OK : S_FALSE;
}

// DllRegisterServer - Register the credential provider
STDAPI DllRegisterServer()
{
    HRESULT hr = S_OK;
    HKEY hKey = NULL;
    WCHAR szCLSID[MAX_PATH] = { 0 };
    WCHAR szKey[MAX_PATH] = { 0 };
    
    // Convert CLSID to string
    StringFromGUID2(CLSID_GEEKSProvider, szCLSID, MAX_PATH);
    
    // Register CLSID
    StringCchPrintfW(szKey, MAX_PATH, L"CLSID\\%s", szCLSID);
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, szKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)L"GEEKS Credential Provider", sizeof(L"GEEKS Credential Provider"));
        RegCloseKey(hKey);
    }
    
    // Register InprocServer32
    StringCchPrintfW(szKey, MAX_PATH, L"CLSID\\%s\\InprocServer32", szCLSID);
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, szKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        WCHAR szModulePath[MAX_PATH] = { 0 };
        GetModuleFileNameW(g_hInst, szModulePath, MAX_PATH);
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)szModulePath, (wcslen(szModulePath) + 1) * sizeof(WCHAR));
        RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ, (BYTE*)L"Apartment", sizeof(L"Apartment"));
        RegCloseKey(hKey);
    }
    
    // Register credential provider
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)L"GEEKS Credential Provider", sizeof(L"GEEKS Credential Provider"));
        RegCloseKey(hKey);
    }
    
    // Create configuration registry key
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, GEEKS_REGISTRY_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        DWORD dwValue = 1;
        RegSetValueExW(hKey, GEEKS_REGISTRY_VALUE_ENABLED, 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        
        dwValue = 0;
        RegSetValueExW(hKey, GEEKS_REGISTRY_VALUE_DEBUG, 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        
        RegSetValueExW(hKey, GEEKS_REGISTRY_VALUE_PORTAL_URL, 0, REG_SZ, (BYTE*)GEEKS_DEFAULT_PORTAL_URL, sizeof(GEEKS_DEFAULT_PORTAL_URL));
        
        RegCloseKey(hKey);
    }
    
    return hr;
}

// DllUnregisterServer - Unregister the credential provider
STDAPI DllUnregisterServer()
{
    HRESULT hr = S_OK;
    WCHAR szCLSID[MAX_PATH] = { 0 };
    WCHAR szKey[MAX_PATH] = { 0 };
    
    // Convert CLSID to string
    StringFromGUID2(CLSID_GEEKSProvider, szCLSID, MAX_PATH);
    
    // Unregister CLSID
    StringCchPrintfW(szKey, MAX_PATH, L"CLSID\\%s", szCLSID);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, szKey);
    
    // Unregister credential provider
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}");
    
    // Remove configuration registry key
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, GEEKS_REGISTRY_KEY);
    
    return hr;
} 