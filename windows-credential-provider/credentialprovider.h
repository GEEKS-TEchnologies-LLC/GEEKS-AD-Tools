#pragma once

#include <windows.h>
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
#define GEEKS_CREDENTIAL_PROVIDER_GUID L"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

// Field IDs
#define GEEKS_CP_FIELD_ID_SUBMIT_BUTTON 1
#define GEEKS_CP_FIELD_ID_FORGOT_PASSWORD 2

// Field types
#define GEEKS_CP_FIELD_TYPE_SUBMIT_BUTTON 1
#define GEEKS_CP_FIELD_TYPE_FORGOT_PASSWORD 2

// Registry keys
#define GEEKS_REGISTRY_KEY L"SOFTWARE\\GEEKS\\CredentialProvider"
#define GEEKS_REGISTRY_VALUE_PORTAL_URL L"PortalURL"
#define GEEKS_REGISTRY_VALUE_ENABLED L"Enabled"
#define GEEKS_REGISTRY_VALUE_DEBUG L"Debug"

// Default portal URL
#define GEEKS_DEFAULT_PORTAL_URL L"http://localhost:5000/reset-password"

// Class forward declarations
class CGEEKSProvider;
class CGEEKSCredential;

// GEEKS Credential Provider Class
class CGEEKSProvider : public ICredentialProvider
{
public:
    // IUnknown
    STDMETHODIMP_(ULONG) AddRef() { return ++_cRef; }
    STDMETHODIMP_(ULONG) Release();
    STDMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv);

    // ICredentialProvider
    STDMETHODIMP SetUsageScenario(_In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, _In_ DWORD dwFlags);
    STDMETHODIMP SetSerialization(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    STDMETHODIMP Advise(_In_ ICredentialProviderEvents* cpEvents);
    STDMETHODIMP UnAdvise();
    STDMETHODIMP GetFieldDescriptorCount(_Out_ DWORD* pdwCount);
    STDMETHODIMP GetFieldDescriptorAt(_In_ DWORD dwIndex, _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    STDMETHODIMP GetCredentialAt(_In_ DWORD dwIndex, _Outptr_result_nullonfailure_ ICredential** ppcpc);
    STDMETHODIMP GetCredentialCount(_Out_ DWORD* pdwCount, _Out_ DWORD* pdwDefault, _Out_ BOOL* pbAutoLogonWithDefault);
    STDMETHODIMP GetFieldDescriptorAt(_In_ DWORD dwIndex, _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    // Constructor and destructor
    CGEEKSProvider();
    ~CGEEKSProvider();

    // Helper methods
    HRESULT Initialize();
    BOOL IsEnabled();
    LPCWSTR GetPortalURL();

private:
    long _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    ICredentialProviderEvents* _pCredentialProviderEvents;
    CGEEKSCredential* _pCredential;
    BOOL _bEnabled;
    WCHAR _szPortalURL[MAX_PATH];
    BOOL _bDebug;

    // Helper methods
    HRESULT LoadConfiguration();
    void LogDebugMessage(LPCWSTR szMessage);
};

// GEEKS Credential Class
class CGEEKSCredential : public ICredential
{
public:
    // IUnknown
    STDMETHODIMP_(ULONG) AddRef() { return ++_cRef; }
    STDMETHODIMP_(ULONG) Release();
    STDMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv);

    // ICredential
    STDMETHODIMP Advise(_In_ ICredentialProviderCredentialEvents* pcpce);
    STDMETHODIMP UnAdvise();
    STDMETHODIMP SetSelected(_Out_ BOOL* pbAutoLogon);
    STDMETHODIMP SetDeselected();
    STDMETHODIMP GetFieldState(_In_ DWORD dwFieldID, _Out_ CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    STDMETHODIMP GetStringValue(_In_ DWORD dwFieldID, _Outptr_result_nullonfailure_ LPWSTR* ppwz);
    STDMETHODIMP GetBitmapValue(_In_ DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP* phbmp);
    STDMETHODIMP GetCheckboxValue(_In_ DWORD dwFieldID, _Out_ BOOL* pbChecked, _Outptr_result_nullonfailure_ LPWSTR* ppwzLabel);
    STDMETHODIMP GetSubmitButtonValue(_In_ DWORD dwFieldID, _Out_ DWORD* pdwAdjacentTo);
    STDMETHODIMP GetComboBoxValueCount(_In_ DWORD dwFieldID, _Out_ DWORD* pcItems, _Out_range_(<, pcItems) DWORD* pdwSelectedItem);
    STDMETHODIMP GetComboBoxValueAt(_In_ DWORD dwFieldID, _In_ DWORD dwItem, _Outptr_result_nullonfailure_ LPWSTR* ppwzItem);
    STDMETHODIMP SetStringValue(_In_ DWORD dwFieldID, _In_ LPCWSTR pwz);
    STDMETHODIMP SetCheckboxValue(_In_ DWORD dwFieldID, _In_ BOOL bChecked);
    STDMETHODIMP SetComboBoxSelectedValue(_In_ DWORD dwFieldID, _In_ DWORD dwSelectedItem);
    STDMETHODIMP DeleteValue(_In_ DWORD dwFieldID);
    STDMETHODIMP GetUserSid(_Outptr_result_nullonfailure_ PSID* ppsid);
    STDMETHODIMP GetProviderID(_Out_ GUID* pguidProviderID);
    STDMETHODIMP GetCredentialAt(_In_ DWORD dwIndex, _Outptr_result_nullonfailure_ ICredential** ppcpc);

    // Constructor and destructor
    CGEEKSCredential();
    ~CGEEKSCredential();

    // Helper methods
    HRESULT Initialize(CGEEKSProvider* pProvider);
    HRESULT LaunchPortal();
    void LogDebugMessage(LPCWSTR szMessage);

private:
    long _cRef;
    CGEEKSProvider* _pProvider;
    ICredentialProviderCredentialEvents* _pCredentialProviderCredentialEvents;
    BOOL _bSelected;
    WCHAR _szPortalURL[MAX_PATH];
    BOOL _bDebug;
};

// Helper functions
HRESULT CreateGEEKSProvider(REFIID riid, void** ppv);
void LogEvent(LPCWSTR szMessage, WORD wType = EVENTLOG_INFORMATION_TYPE);
BOOL IsElevated();
BOOL IsDomainController();
BOOL IsWorkstation();
BOOL IsServer();
BOOL IsWindows10OrLater();
BOOL IsWindowsServer2016OrLater(); 