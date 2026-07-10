#pragma once

// Minimal WinDivert 2.2.x ABI declarations used by EasyWG Server.
// WinDivert project: https://reqrypt.org/windivert.html
// The runtime is dynamically loaded; no import library is required.

#include <windows.h>
#include <cstdint>

typedef enum
{
    WINDIVERT_LAYER_NETWORK = 0,
    WINDIVERT_LAYER_NETWORK_FORWARD = 1,
    WINDIVERT_LAYER_FLOW = 2,
    WINDIVERT_LAYER_SOCKET = 3,
    WINDIVERT_LAYER_REFLECT = 4,
} WINDIVERT_LAYER;

typedef struct
{
    UINT32 IfIdx;
    UINT32 SubIfIdx;
} WINDIVERT_DATA_NETWORK;

typedef struct
{
    UINT64 EndpointId;
    UINT64 ParentEndpointId;
    UINT32 ProcessId;
    UINT32 LocalAddr[4];
    UINT32 RemoteAddr[4];
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT8 Protocol;
} WINDIVERT_DATA_FLOW;

typedef struct
{
    UINT64 EndpointId;
    UINT64 ParentEndpointId;
    UINT32 ProcessId;
    UINT32 LocalAddr[4];
    UINT32 RemoteAddr[4];
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT8 Protocol;
} WINDIVERT_DATA_SOCKET;

typedef struct
{
    INT64 Timestamp;
    UINT32 ProcessId;
    WINDIVERT_LAYER Layer;
    UINT64 Flags;
    INT16 Priority;
} WINDIVERT_DATA_REFLECT;

#pragma warning(push)
#pragma warning(disable: 4201 4214)
typedef struct
{
    INT64 Timestamp;
    UINT64 Layer : 8;
    UINT64 Event : 8;
    UINT64 Sniffed : 1;
    UINT64 Outbound : 1;
    UINT64 Loopback : 1;
    UINT64 Impostor : 1;
    UINT64 IPv6 : 1;
    UINT64 IPChecksum : 1;
    UINT64 TCPChecksum : 1;
    UINT64 UDPChecksum : 1;
    union
    {
        WINDIVERT_DATA_NETWORK Network;
        WINDIVERT_DATA_FLOW Flow;
        WINDIVERT_DATA_SOCKET Socket;
        WINDIVERT_DATA_REFLECT Reflect;
    };
} WINDIVERT_ADDRESS;
#pragma warning(pop)

typedef enum
{
    WINDIVERT_PARAM_QUEUE_LENGTH = 0,
    WINDIVERT_PARAM_QUEUE_TIME = 1,
    WINDIVERT_PARAM_QUEUE_SIZE = 2,
    WINDIVERT_PARAM_VERSION_MAJOR = 3,
    WINDIVERT_PARAM_VERSION_MINOR = 4,
} WINDIVERT_PARAM;

typedef enum
{
    WINDIVERT_SHUTDOWN_RECV = 0x1,
    WINDIVERT_SHUTDOWN_SEND = 0x2,
    WINDIVERT_SHUTDOWN_BOTH = 0x3,
} WINDIVERT_SHUTDOWN;

#pragma warning(push)
#pragma warning(disable: 4214)
typedef struct
{
    UINT8 HdrLength : 4;
    UINT8 Version : 4;
    UINT8 TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8 TTL;
    UINT8 Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
} WINDIVERT_IPHDR;

typedef struct
{
    UINT8 Type;
    UINT8 Code;
    UINT16 Checksum;
    UINT32 Body;
} WINDIVERT_ICMPHDR;

typedef struct
{
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1 : 4;
    UINT16 HdrLength : 4;
    UINT16 Fin : 1;
    UINT16 Syn : 1;
    UINT16 Rst : 1;
    UINT16 Psh : 1;
    UINT16 Ack : 1;
    UINT16 Urg : 1;
    UINT16 Reserved2 : 2;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 UrgPtr;
} WINDIVERT_TCPHDR;

typedef struct
{
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT16 Length;
    UINT16 Checksum;
} WINDIVERT_UDPHDR;
#pragma warning(pop)

#if defined(__cplusplus)
static_assert(sizeof(WINDIVERT_ADDRESS) == 80, "Unexpected WinDivert 2.2 WINDIVERT_ADDRESS ABI");
static_assert(sizeof(WINDIVERT_IPHDR) == 20, "Unexpected IPv4 header ABI");
static_assert(sizeof(WINDIVERT_ICMPHDR) == 8, "Unexpected ICMP header ABI");
static_assert(sizeof(WINDIVERT_TCPHDR) == 20, "Unexpected TCP header ABI");
static_assert(sizeof(WINDIVERT_UDPHDR) == 8, "Unexpected UDP header ABI");
#endif

#define WINDIVERT_FLAG_SNIFF      0x0001
#define WINDIVERT_FLAG_DROP       0x0002
#define WINDIVERT_FLAG_RECV_ONLY  0x0004
#define WINDIVERT_FLAG_SEND_ONLY  0x0008
#define WINDIVERT_FLAG_NO_INSTALL 0x0010
#define WINDIVERT_FLAG_FRAGMENTS  0x0020

using WINDIVERT_OPEN_FUNC = HANDLE(const char*, WINDIVERT_LAYER, INT16, UINT64);
using WINDIVERT_RECV_FUNC = BOOL(HANDLE, VOID*, UINT, UINT*, WINDIVERT_ADDRESS*);
using WINDIVERT_SEND_FUNC = BOOL(HANDLE, const VOID*, UINT, UINT*, const WINDIVERT_ADDRESS*);
using WINDIVERT_SHUTDOWN_FUNC = BOOL(HANDLE, WINDIVERT_SHUTDOWN);
using WINDIVERT_CLOSE_FUNC = BOOL(HANDLE);
using WINDIVERT_SET_PARAM_FUNC = BOOL(HANDLE, WINDIVERT_PARAM, UINT64);
using WINDIVERT_HELPER_CALC_CHECKSUMS_FUNC = BOOL(VOID*, UINT, WINDIVERT_ADDRESS*, UINT64);
