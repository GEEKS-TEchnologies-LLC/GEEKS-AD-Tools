# Windows Credential Provider

This folder contains a template for a custom Windows Credential Provider that adds a "Forgot Password?" tile to the Windows lock screen. When clicked, it launches the default browser to your password reset portal.

## Prerequisites
- Visual Studio (with Desktop development with C++ workload)
- Windows SDK
- (Optional for production) Code signing certificate

## Build Instructions
1. Open Visual Studio and create a new DLL project (or use the provided files).
2. Add the provided source/header files to your project:
   - credentialprovider.h / credentialprovider.cpp
   - guid.h
   - dllmain.cpp
   - dll.def
3. Edit `credentialprovider.cpp` to set your password reset portal URL (e.g., `L"http://your-server/reset"`).
4. Build the project (Release x64 recommended).
5. (Optional but recommended) Sign the DLL with your code signing certificate:
   - Use `signtool.exe` (included with Visual Studio):
     ```sh
     signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 /v path\to\ForgotPasswordProvider.dll
     ```

## Deployment Instructions

### Manual Deployment
1. Copy the built and signed DLL to a folder on the target machine (e.g., `C:\Program Files\ForgotPasswordProvider\`).
2. Register the Credential Provider in the registry:
   - Open `regedit.exe` as Administrator.
   - Navigate to:
     ```
     HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers
     ```
   - Create a new key with the name of your provider's GUID (see `guid.h`). Example:
     ```
     {D1A5B6C7-1234-4E5F-8A9B-1234567890AB}
     ```
   - Set the default value to the path of your DLL (e.g., `C:\Program Files\ForgotPasswordProvider\ForgotPasswordProvider.dll`).
3. Restart the computer or log off/log on to see the new tile on the lock screen.

### Group Policy Deployment (Recommended for Enterprises)
1. Copy the DLL to a network share accessible by all target machines.
2. Use Group Policy to deploy the DLL and registry settings:
   - Create a Group Policy Object (GPO) for Credential Provider deployment.
   - Use the "File" preference to copy the DLL to each machine.
   - Use the "Registry" preference to add the provider's GUID and DLL path as above.
   - Optionally, use a startup script to register the DLL if needed.
3. Update Group Policy on target machines (`gpupdate /force`).
4. Verify the tile appears on the lock screen.

## Uninstallation
1. Remove the registry key for your provider's GUID.
2. Delete the DLL from the system.
3. Restart the computer.

## Customization
- Edit the URL in the C++ code to point to your password reset portal (e.g., `http://your-server/reset`).
- Customize the tile text and icon as needed.

## References
- [Microsoft Credential Provider documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Credential Provider sample code (GitHub)](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Security/CredProvider) 