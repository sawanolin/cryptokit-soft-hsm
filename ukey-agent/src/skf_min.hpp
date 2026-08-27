#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

using SKF_ULONG = uint32_t;
using SKF_BOOL = int32_t;
using SKF_BYTE = unsigned char;
using SKF_HANDLE = void *;

constexpr SKF_ULONG SAR_OK = 0x00000000;
constexpr SKF_ULONG SGD_SM3 = 0x00000001;
constexpr SKF_ULONG USER_TYPE = 1;

struct ECCPUBLICKEYBLOB {
    SKF_ULONG BitLen;
    SKF_BYTE XCoordinate[64];
    SKF_BYTE YCoordinate[64];
};

struct ECCSIGNATUREBLOB {
    SKF_BYTE r[64];
    SKF_BYTE s[64];
};

using FnEnumDev = SKF_ULONG(WINAPI *)(SKF_BOOL, char *, SKF_ULONG *);
using FnConnectDev = SKF_ULONG(WINAPI *)(char *, SKF_HANDLE *);
using FnDisconnectDev = SKF_ULONG(WINAPI *)(SKF_HANDLE);
using FnEnumApplication = SKF_ULONG(WINAPI *)(SKF_HANDLE, char *, SKF_ULONG *);
using FnOpenApplication = SKF_ULONG(WINAPI *)(SKF_HANDLE, char *, SKF_HANDLE *);
using FnCloseApplication = SKF_ULONG(WINAPI *)(SKF_HANDLE);
using FnVerifyPIN = SKF_ULONG(WINAPI *)(SKF_HANDLE, SKF_ULONG, char *, SKF_ULONG *);
using FnClearSecureState = SKF_ULONG(WINAPI *)(SKF_HANDLE);
using FnEnumContainer = SKF_ULONG(WINAPI *)(SKF_HANDLE, char *, SKF_ULONG *);
using FnOpenContainer = SKF_ULONG(WINAPI *)(SKF_HANDLE, char *, SKF_HANDLE *);
using FnCloseContainer = SKF_ULONG(WINAPI *)(SKF_HANDLE);
using FnExportPublicKey = SKF_ULONG(WINAPI *)(SKF_HANDLE, SKF_BOOL, SKF_BYTE *, SKF_ULONG *);
using FnExportCertificate = SKF_ULONG(WINAPI *)(SKF_HANDLE, SKF_BOOL, SKF_BYTE *, SKF_ULONG *);
using FnDigestInit = SKF_ULONG(WINAPI *)(SKF_HANDLE, SKF_ULONG, ECCPUBLICKEYBLOB *,
                                         SKF_BYTE *, SKF_ULONG, SKF_HANDLE *);
using FnDigestUpdate = SKF_ULONG(WINAPI *)(SKF_HANDLE, SKF_BYTE *, SKF_ULONG);
using FnDigestFinal = SKF_ULONG(WINAPI *)(SKF_HANDLE, SKF_BYTE *, SKF_ULONG *);
using FnCloseHandle = SKF_ULONG(WINAPI *)(SKF_HANDLE);
using FnECCSignData = SKF_ULONG(WINAPI *)(SKF_HANDLE, SKF_BYTE *, SKF_ULONG,
                                          ECCSIGNATUREBLOB *);

static_assert(sizeof(SKF_ULONG) == 4, "SKF ULONG must be 32-bit");
static_assert(sizeof(ECCPUBLICKEYBLOB) == 132, "unexpected ECC public key layout");
static_assert(sizeof(ECCSIGNATUREBLOB) == 128, "unexpected ECC signature layout");
