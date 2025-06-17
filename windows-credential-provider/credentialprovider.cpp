#include "credentialprovider.h"
#include <credentialprovider.h>
#include <wincred.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <commctrl.h>
#include <ole2.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <winsvc.h>
#include <wininet.h>
#include <shellapi.h>
#include <winreg.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <lm.h>
#include <netapi32.h>
#include <security.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <ntlsa.h>
#include <ntsam.h>
#include <ntdsapi.h>
#include <dsgetdc.h>
#include <dsrole.h>
#include <dsadmin.h>
#include <dsclient.h>
#include <dsquery.h>
#include <dsutil.h>
#include <dssec.h>
#include <dsgetdc.h>
#include <dsrole.h>
#include <dsadmin.h>
#include <dsclient.h>
#include <dsquery.h>
#include <dsutil.h>
#include <dssec.h>

// GEEKS Credential Provider GUID
const CLSID CLSID_GEEKSProvider = { 0xA1B2C3D4, 0xE5F6, 0x7890, { 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90 } };

// Global variables
HINSTANCE g_hInst = NULL;
long g_cDllRef = 0;

// CGEEKSProvider implementation
CGEEKSProvider::CGEEKSProvider() : _cRef(1), _cpus(CPUS_INVALID), _pCredentialProviderEvents(nullptr), _pCredential(nullptr), _bEnabled(TRUE), _bDebug(FALSE)
{
    ZeroMemory(_szPortalURL, sizeof(_szPortalURL));
    StringCchCopyW(_szPortalURL, MAX_PATH, GEEKS_DEFAULT_PORTAL_URL);
    Initialize();
}

CGEEKSProvider::~CGEEKSProvider()
{
    if (_pCredential)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
}

STDMETHODIMP_(ULONG) CGEEKSProvider::Release()
{
    long cRef = --_cRef;
    if (!cRef)
    {
        delete this;
    }
    return cRef;
}

STDMETHODIMP CGEEKSProvider::QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv)
{
    static const QITAB qit[] = {
        QITABENT(CGEEKSProvider, ICredentialProvider),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

STDMETHODIMP CGEEKSProvider::SetUsageScenario(_In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, _In_ DWORD dwFlags)
{
    _cpus = cpus;
    
    // Only show on logon and unlock scenarios
    if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)
    {
        if (!_bEnabled)
        {
            LogDebugMessage(L"GEEKS Credential Provider is disabled");
            return S_OK;
        }
        
        LogDebugMessage(L"GEEKS Credential Provider enabled for usage scenario");
        return S_OK;
    }
    
    return S_OK;
}

STDMETHODIMP CGEEKSProvider::SetSerialization(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSProvider::Advise(_In_ ICredentialProviderEvents* cpEvents)
{
    if (_pCredentialProviderEvents)
    {
        _pCredentialProviderEvents->Release();
    }
    _pCredentialProviderEvents = cpEvents;
    if (_pCredentialProviderEvents)
    {
        _pCredentialProviderEvents->AddRef();
    }
    return S_OK;
}

STDMETHODIMP CGEEKSProvider::UnAdvise()
{
    if (_pCredentialProviderEvents)
    {
        _pCredentialProviderEvents->Release();
        _pCredentialProviderEvents = nullptr;
    }
    return S_OK;
}

STDMETHODIMP CGEEKSProvider::GetFieldDescriptorCount(_Out_ DWORD* pdwCount)
{
    *pdwCount = 2; // Submit button and forgot password field
    return S_OK;
}

STDMETHODIMP CGEEKSProvider::GetFieldDescriptorAt(_In_ DWORD dwIndex, _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr = S_OK;
    
    if (dwIndex >= 2)
    {
        return E_INVALIDARG;
    }
    
    *ppcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!*ppcpfd)
    {
        return E_OUTOFMEMORY;
    }
    
    ZeroMemory(*ppcpfd, sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    
    switch (dwIndex)
    {
    case 0: // Submit button
        (*ppcpfd)->dwFieldID = GEEKS_CP_FIELD_ID_SUBMIT_BUTTON;
        (*ppcpfd)->cpft = CPFT_SUBMIT_BUTTON;
        (*ppcpfd)->pszLabel = (LPWSTR)CoTaskMemAlloc(sizeof(L"Forgot Password?"));
        StringCchCopyW((*ppcpfd)->pszLabel, 16, L"Forgot Password?");
        break;
        
    case 1: // Forgot password field
        (*ppcpfd)->dwFieldID = GEEKS_CP_FIELD_ID_FORGOT_PASSWORD;
        (*ppcpfd)->cpft = CPFT_LARGE_TEXT;
        (*ppcpfd)->pszLabel = (LPWSTR)CoTaskMemAlloc(sizeof(L"Click 'Forgot Password?' to reset your password"));
        StringCchCopyW((*ppcpfd)->pszLabel, 50, L"Click 'Forgot Password?' to reset your password");
        break;
    }
    
    return hr;
}

STDMETHODIMP CGEEKSProvider::GetCredentialAt(_In_ DWORD dwIndex, _Outptr_result_nullonfailure_ ICredential** ppcpc)
{
    HRESULT hr = S_OK;
    
    if (dwIndex != 0)
    {
        return E_INVALIDARG;
    }
    
    if (!_pCredential)
    {
        _pCredential = new CGEEKSCredential();
        if (!_pCredential)
        {
            return E_OUTOFMEMORY;
        }
        
        hr = _pCredential->Initialize(this);
        if (FAILED(hr))
        {
            _pCredential->Release();
            _pCredential = nullptr;
            return hr;
        }
    }
    
    *ppcpc = _pCredential;
    (*ppcpc)->AddRef();
    
    return hr;
}

STDMETHODIMP CGEEKSProvider::GetCredentialCount(_Out_ DWORD* pdwCount, _Out_ DWORD* pdwDefault, _Out_ BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

HRESULT CGEEKSProvider::Initialize()
{
    return LoadConfiguration();
}

BOOL CGEEKSProvider::IsEnabled()
{
    return _bEnabled;
}

LPCWSTR CGEEKSProvider::GetPortalURL()
{
    return _szPortalURL;
}

HRESULT CGEEKSProvider::LoadConfiguration()
{
    HKEY hKey = NULL;
    LONG lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, GEEKS_REGISTRY_KEY, 0, KEY_READ, &hKey);
    
    if (lResult == ERROR_SUCCESS)
    {
        DWORD dwValue = 1;
        DWORD dwSize = sizeof(DWORD);
        RegQueryValueExW(hKey, GEEKS_REGISTRY_VALUE_ENABLED, NULL, NULL, (LPBYTE)&dwValue, &dwSize);
        _bEnabled = (dwValue != 0);
        
        dwValue = 0;
        RegQueryValueExW(hKey, GEEKS_REGISTRY_VALUE_DEBUG, NULL, NULL, (LPBYTE)&dwValue, &dwSize);
        _bDebug = (dwValue != 0);
        
        WCHAR szURL[MAX_PATH] = { 0 };
        dwSize = sizeof(szURL);
        if (RegQueryValueExW(hKey, GEEKS_REGISTRY_VALUE_PORTAL_URL, NULL, NULL, (LPBYTE)szURL, &dwSize) == ERROR_SUCCESS)
        {
            StringCchCopyW(_szPortalURL, MAX_PATH, szURL);
        }
        
        RegCloseKey(hKey);
    }
    
    LogDebugMessage(L"Configuration loaded");
    return S_OK;
}

void CGEEKSProvider::LogDebugMessage(LPCWSTR szMessage)
{
    if (_bDebug)
    {
        LogEvent(szMessage, EVENTLOG_INFORMATION_TYPE);
    }
}

// CGEEKSCredential implementation
CGEEKSCredential::CGEEKSCredential() : _cRef(1), _pProvider(nullptr), _pCredentialProviderCredentialEvents(nullptr), _bSelected(FALSE), _bDebug(FALSE)
{
    ZeroMemory(_szPortalURL, sizeof(_szPortalURL));
}

CGEEKSCredential::~CGEEKSCredential()
{
    if (_pProvider)
    {
        _pProvider->Release();
        _pProvider = nullptr;
    }
}

STDMETHODIMP_(ULONG) CGEEKSCredential::Release()
{
    long cRef = --_cRef;
    if (!cRef)
    {
        delete this;
    }
    return cRef;
}

STDMETHODIMP CGEEKSCredential::QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv)
{
    static const QITAB qit[] = {
        QITABENT(CGEEKSCredential, ICredential),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

STDMETHODIMP CGEEKSCredential::Advise(_In_ ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredentialProviderCredentialEvents)
    {
        _pCredentialProviderCredentialEvents->Release();
    }
    _pCredentialProviderCredentialEvents = pcpce;
    if (_pCredentialProviderCredentialEvents)
    {
        _pCredentialProviderCredentialEvents->AddRef();
    }
    return S_OK;
}

STDMETHODIMP CGEEKSCredential::UnAdvise()
{
    if (_pCredentialProviderCredentialEvents)
    {
        _pCredentialProviderCredentialEvents->Release();
        _pCredentialProviderCredentialEvents = nullptr;
    }
    return S_OK;
}

STDMETHODIMP CGEEKSCredential::SetSelected(_Out_ BOOL* pbAutoLogon)
{
    _bSelected = TRUE;
    *pbAutoLogon = FALSE;
    return S_OK;
}

STDMETHODIMP CGEEKSCredential::SetDeselected()
{
    _bSelected = FALSE;
    return S_OK;
}

STDMETHODIMP CGEEKSCredential::GetFieldState(_In_ DWORD dwFieldID, _Out_ CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    switch (dwFieldID)
    {
    case GEEKS_CP_FIELD_ID_SUBMIT_BUTTON:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        break;
        
    case GEEKS_CP_FIELD_ID_FORGOT_PASSWORD:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_NONE;
        break;
        
    default:
        return E_INVALIDARG;
    }
    
    return S_OK;
}

STDMETHODIMP CGEEKSCredential::GetStringValue(_In_ DWORD dwFieldID, _Outptr_result_nullonfailure_ LPWSTR* ppwz)
{
    switch (dwFieldID)
    {
    case GEEKS_CP_FIELD_ID_FORGOT_PASSWORD:
        *ppwz = (LPWSTR)CoTaskMemAlloc(sizeof(L"Click 'Forgot Password?' to reset your password"));
        StringCchCopyW(*ppwz, 50, L"Click 'Forgot Password?' to reset your password");
        return S_OK;
        
    default:
        return E_INVALIDARG;
    }
}

STDMETHODIMP CGEEKSCredential::GetBitmapValue(_In_ DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP* phbmp)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::GetCheckboxValue(_In_ DWORD dwFieldID, _Out_ BOOL* pbChecked, _Outptr_result_nullonfailure_ LPWSTR* ppwzLabel)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::GetSubmitButtonValue(_In_ DWORD dwFieldID, _Out_ DWORD* pdwAdjacentTo)
{
    if (dwFieldID == GEEKS_CP_FIELD_ID_SUBMIT_BUTTON)
    {
        *pdwAdjacentTo = GEEKS_CP_FIELD_ID_FORGOT_PASSWORD;
        return S_OK;
    }
    
    return E_INVALIDARG;
}

STDMETHODIMP CGEEKSCredential::GetComboBoxValueCount(_In_ DWORD dwFieldID, _Out_ DWORD* pcItems, _Out_range_(<, pcItems) DWORD* pdwSelectedItem)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::GetComboBoxValueAt(_In_ DWORD dwFieldID, _In_ DWORD dwItem, _Outptr_result_nullonfailure_ LPWSTR* ppwzItem)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::SetStringValue(_In_ DWORD dwFieldID, _In_ LPCWSTR pwz)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::SetCheckboxValue(_In_ DWORD dwFieldID, _In_ BOOL bChecked)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::SetComboBoxSelectedValue(_In_ DWORD dwFieldID, _In_ DWORD dwSelectedItem)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::DeleteValue(_In_ DWORD dwFieldID)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::GetUserSid(_Outptr_result_nullonfailure_ PSID* ppsid)
{
    return E_NOTIMPL;
}

STDMETHODIMP CGEEKSCredential::GetProviderID(_Out_ GUID* pguidProviderID)
{
    *pguidProviderID = CLSID_GEEKSProvider;
    return S_OK;
}

STDMETHODIMP CGEEKSCredential::GetCredentialAt(_In_ DWORD dwIndex, _Outptr_result_nullonfailure_ ICredential** ppcpc)
{
    return E_NOTIMPL;
}

HRESULT CGEEKSCredential::Initialize(CGEEKSProvider* pProvider)
{
    _pProvider = pProvider;
    if (_pProvider)
    {
        _pProvider->AddRef();
        StringCchCopyW(_szPortalURL, MAX_PATH, _pProvider->GetPortalURL());
        _bDebug = _pProvider->IsEnabled();
    }
    
    LogDebugMessage(L"GEEKS Credential initialized");
    return S_OK;
}

HRESULT CGEEKSCredential::LaunchPortal()
{
    LogDebugMessage(L"Launching portal");
    
    // Launch the portal URL in the default browser
    HINSTANCE hResult = ShellExecuteW(NULL, L"open", _szPortalURL, NULL, NULL, SW_SHOWNORMAL);
    
    if ((INT_PTR)hResult <= 32)
    {
        LogEvent(L"Failed to launch portal", EVENTLOG_ERROR_TYPE);
        return E_FAIL;
    }
    
    LogEvent(L"Portal launched successfully", EVENTLOG_INFORMATION_TYPE);
    return S_OK;
}

void CGEEKSCredential::LogDebugMessage(LPCWSTR szMessage)
{
    if (_bDebug)
    {
        LogEvent(szMessage, EVENTLOG_INFORMATION_TYPE);
    }
}

// Helper functions
HRESULT CreateGEEKSProvider(REFIID riid, void** ppv)
{
    CGEEKSProvider* pProvider = new CGEEKSProvider();
    if (!pProvider)
    {
        return E_OUTOFMEMORY;
    }
    
    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

void LogEvent(LPCWSTR szMessage, WORD wType)
{
    HANDLE hEventLog = RegisterEventSourceW(NULL, L"GEEKS-CredentialProvider");
    if (hEventLog)
    {
        LPCWSTR lpStrings[] = { szMessage };
        ReportEventW(hEventLog, wType, 0, 0, NULL, 1, 0, lpStrings, NULL);
        DeregisterEventSource(hEventLog);
    }
}

BOOL IsElevated()
{
    BOOL bIsElevated = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD dwSize = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
        {
            bIsElevated = elevation.TokenIsElevated;
        }
        
        CloseHandle(hToken);
    }
    
    return bIsElevated;
}

BOOL IsDomainController()
{
    DSROLE_PRIMARY_DOMAIN_INFO_BASIC* pInfo = NULL;
    DWORD dwError = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (BYTE**)&pInfo);
    
    if (dwError == ERROR_SUCCESS)
    {
        BOOL bIsDC = (pInfo->MachineRole == DsRole_RolePrimaryDomainController || 
                      pInfo->MachineRole == DsRole_RoleBackupDomainController);
        DsRoleFreeMemory(pInfo);
        return bIsDC;
    }
    
    return FALSE;
}

BOOL IsWorkstation()
{
    DSROLE_PRIMARY_DOMAIN_INFO_BASIC* pInfo = NULL;
    DWORD dwError = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (BYTE**)&pInfo);
    
    if (dwError == ERROR_SUCCESS)
    {
        BOOL bIsWorkstation = (pInfo->MachineRole == DsRole_RoleMemberWorkstation);
        DsRoleFreeMemory(pInfo);
        return bIsWorkstation;
    }
    
    return FALSE;
}

BOOL IsServer()
{
    DSROLE_PRIMARY_DOMAIN_INFO_BASIC* pInfo = NULL;
    DWORD dwError = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (BYTE**)&pInfo);
    
    if (dwError == ERROR_SUCCESS)
    {
        BOOL bIsServer = (pInfo->MachineRole == DsRole_RoleMemberServer);
        DsRoleFreeMemory(pInfo);
        return bIsServer;
    }
    
    return FALSE;
}

BOOL IsWindows10OrLater()
{
    OSVERSIONINFOEXW osvi = { sizeof(OSVERSIONINFOEXW) };
    DWORDLONG dwlConditionMask = 0;
    
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);
    
    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;
    osvi.dwBuildNumber = 0;
    
    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, dwlConditionMask);
}

BOOL IsWindowsServer2016OrLater()
{
    OSVERSIONINFOEXW osvi = { sizeof(OSVERSIONINFOEXW) };
    DWORDLONG dwlConditionMask = 0;
    
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);
    
    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;
    osvi.dwBuildNumber = 14393;
    
    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, dwlConditionMask);
} 