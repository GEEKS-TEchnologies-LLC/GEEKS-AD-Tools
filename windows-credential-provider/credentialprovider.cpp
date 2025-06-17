#include "credentialprovider.h"
#include <shlobj.h>
#include <shellapi.h>

ForgotPasswordProvider::ForgotPasswordProvider() : _cRef(1) {}
ForgotPasswordProvider::~ForgotPasswordProvider() {}

// IUnknown
IFACEMETHODIMP ForgotPasswordProvider::QueryInterface(REFIID riid, void** ppv) {
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}
IFACEMETHODIMP_(ULONG) ForgotPasswordProvider::AddRef() { return InterlockedIncrement(&_cRef); }
IFACEMETHODIMP_(ULONG) ForgotPasswordProvider::Release() {
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

// ICredentialProvider (minimal, only one tile)
IFACEMETHODIMP ForgotPasswordProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO, DWORD) { return S_OK; }
IFACEMETHODIMP ForgotPasswordProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }
IFACEMETHODIMP ForgotPasswordProvider::Advise(ICredentialProviderEvents*, UINT_PTR) { return S_OK; }
IFACEMETHODIMP ForgotPasswordProvider::UnAdvise() { return S_OK; }
IFACEMETHODIMP ForgotPasswordProvider::GetFieldDescriptorCount(DWORD* pdwCount) { *pdwCount = 1; return S_OK; }
IFACEMETHODIMP ForgotPasswordProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    static CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR desc = { 0 };
    desc.dwFieldID = 0;
    desc.cpft = CPFT_COMMAND_LINK;
    desc.pszLabel = L"Forgot Password?";
    *ppcpfd = &desc;
    return S_OK;
}
IFACEMETHODIMP ForgotPasswordProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogon) {
    *pdwCount = 1; *pdwDefault = 0; *pbAutoLogon = FALSE; return S_OK;
}
IFACEMETHODIMP ForgotPasswordProvider::GetCredentialAt(DWORD, ICredentialProviderCredential** ppCredential) {
    // Minimal: Launch browser to reset portal (replace URL as needed)
    ShellExecuteW(NULL, L"open", L"http://your-server/reset", NULL, NULL, SW_SHOWNORMAL);
    *ppCredential = nullptr;
    return S_OK;
} 