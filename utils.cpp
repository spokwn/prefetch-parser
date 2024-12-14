#include "include.h"
#include <mscat.h>

std::string ConvertExecutedTime(long long executed_time) {
    std::time_t time = static_cast<std::time_t>(executed_time);
    std::tm tm_time;
    localtime_s(&tm_time, &time);
    std::ostringstream oss;
    oss << std::put_time(&tm_time, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string getOwnPath() {
    char buffer[MAX_PATH];
    DWORD filename = GetModuleFileNameA(NULL, buffer, MAX_PATH);

    return std::string(buffer, filename);
}

std::wstring ToUpperCase(const std::wstring& str) {
    std::wstring upperStr = str;
    std::transform(upperStr.begin(), upperStr.end(), upperStr.begin(),
        [](wchar_t c) { return towupper(c); });
    return upperStr;
}

std::unordered_map<std::wstring, std::wstring> GetVolumeSerialToLetterMap() {
    std::unordered_map<std::wstring, std::wstring> volumeToLetter;

    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return volumeToLetter;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return volumeToLetter;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return volumeToLetter;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0,
        NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return volumeToLetter;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return volumeToLetter;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"),
        bstr_t("SELECT DeviceID, VolumeSerialNumber FROM Win32_LogicalDisk"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);

    if (SUCCEEDED(hres)) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp1, vtProp2;
            hres = pclsObj->Get(L"VolumeSerialNumber", 0, &vtProp1, 0, 0);
            HRESULT hr2 = pclsObj->Get(L"DeviceID", 0, &vtProp2, 0, 0);

            if (SUCCEEDED(hres) && SUCCEEDED(hr2) &&
                vtProp1.vt == VT_BSTR && vtProp2.vt == VT_BSTR) {
                std::wstring serialNum = vtProp1.bstrVal;
                std::wstring driveLetter = vtProp2.bstrVal;

                // Convert serial to uppercase for case-insensitive comparison
                std::transform(serialNum.begin(), serialNum.end(), serialNum.begin(), ::toupper);

                volumeToLetter[serialNum] = driveLetter;
            }

            VariantClear(&vtProp1);
            VariantClear(&vtProp2);
            pclsObj->Release();
        }
    }

    pSvc->Release();
    pLoc->Release();
    if (pEnumerator) pEnumerator->Release();
    CoUninitialize();

    return volumeToLetter;
}

std::wstring GetDriveLetterFromVolumePath(const std::wstring& volumePath) {
    static std::unordered_map<std::wstring, std::wstring> volumeToLetter = GetVolumeSerialToLetterMap();

    size_t startPos = volumePath.find(L"VOLUME{");
    if (startPos == std::wstring::npos) return volumePath;

    size_t endPos = volumePath.find(L'}', startPos);
    if (endPos == std::wstring::npos) return volumePath;

    std::wstring fullVolumeId = volumePath.substr(startPos + 7, endPos - startPos - 7);

    size_t dashPos = fullVolumeId.find(L'-');
    if (dashPos == std::wstring::npos) return volumePath;

    std::wstring serialNumber = fullVolumeId.substr(dashPos + 1);

    std::transform(serialNumber.begin(), serialNumber.end(), serialNumber.begin(), ::toupper);


    auto it = volumeToLetter.find(serialNumber);
    if (it != volumeToLetter.end()) {
        return it->second + volumePath.substr(endPos + 1);
    }

    return volumePath;
}

std::string GetFileTimeString(const FILETIME& fileTime) {
    SYSTEMTIME systemTime;
    FileTimeToSystemTime(&fileTime, &systemTime);
    char buffer[32];
    sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
        systemTime.wYear, systemTime.wMonth, systemTime.wDay,
        systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
    return std::string(buffer);
}

static bool VerifyFileViaCatalog(LPCWSTR filePath)
{
    HANDLE hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
        return false;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    DWORD dwHashSize = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0))
    {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    BYTE* pbHash = new BYTE[dwHashSize];
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0))
    {
        delete[] pbHash;
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    CloseHandle(hFile);

    CATALOG_INFO catInfo = { 0 };
    catInfo.cbStruct = sizeof(catInfo);

    HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
    bool isCatalogSigned = false;

    while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
    {
        WINTRUST_CATALOG_INFO wtc = {};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        wtc.pbCalculatedFileHash = pbHash;
        wtc.cbCalculatedFileHash = dwHashSize;
        wtc.pcwszMemberFilePath = filePath;

        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwProvFlags = 0;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG res = WinVerifyTrust(NULL, &action, &wtd);

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);

        if (res == ERROR_SUCCESS)
        {
            isCatalogSigned = true;
            break;
        }
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, &hCatInfo);
    }

    if (hCatInfo)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    delete[] pbHash;

    return isCatalogSigned;
}


bool IsFileSignatureValid(const std::wstring& filePath) {
    
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData;
    ZeroMemory(&winTrustData, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.pFile = &fileInfo;

    LONG lStatus = WinVerifyTrust(NULL, &guidAction, &winTrustData);
    bool isValid = true;

    if (lStatus != ERROR_SUCCESS) {
        isValid = false; // not signed
        if (VerifyFileViaCatalog(filePath.c_str())) {
            isValid = true;
        }
    }
    else {
        CRYPT_PROVIDER_DATA const* psProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (psProvData) {
            CRYPT_PROVIDER_DATA* nonConstProvData = const_cast<CRYPT_PROVIDER_DATA*>(psProvData);
            CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(nonConstProvData, 0, FALSE, 0);
            if (pProvSigner) {
                CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
                if (pProvCert && pProvCert->pCert) {
                    char subjectName[256];
                    CertNameToStrA(pProvCert->pCert->dwCertEncodingType,
                        &pProvCert->pCert->pCertInfo->Subject,
                        CERT_X500_NAME_STR,
                        subjectName,
                        sizeof(subjectName));

                    std::string subject(subjectName);
                    std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);

                    // vape or slinky check
                    if (subject.find("manthe industries, llc") != std::string::npos ||
                        subject.find("slinkware") != std::string::npos) {
                        isValid = false;
                    }
                }
            }
        }
        
    }
    
    // Cleanup
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return isValid;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty())
        return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty())
        return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}
