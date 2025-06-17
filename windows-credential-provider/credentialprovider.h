#pragma once
#include <windows.h>
#include <credentialprovider.h>

// {D1A5B6C7-1234-4E5F-8A9B-1234567890AB} (example GUID, generate your own for production)
DEFINE_GUID(CLSID_ForgotPasswordProvider, \
0xd1a5b6c7, 0x1234, 0x4e5f, 0x8a, 0x9b, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab);

class ForgotPasswordProvider : public ICredentialProvider {
public:
    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO, DWORD) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents*, UINT_PTR) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD*) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR**) override;
    IFACEMETHODIMP GetCredentialCount(DWORD*, DWORD*, BOOL*) override;
    IFACEMETHODIMP GetCredentialAt(DWORD, ICredentialProviderCredential**) override;

    ForgotPasswordProvider();
    ~ForgotPasswordProvider();

private:
    LONG _cRef;
}; 