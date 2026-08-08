#pragma once

#include <guiddef.h>

// Runtime callouts registered by the kernel driver and referenced by the
// helper's dynamic WFP management objects.
// {0B7E42E1-06BA-4777-84D5-BF99480DE6CE}
DEFINE_GUID(MOUSEVPN_CALLOUT_CONNECT_V4,
    0x0b7e42e1, 0x06ba, 0x4777, 0x84, 0xd5, 0xbf, 0x99, 0x48, 0x0d, 0xe6, 0xce);
// {02B4A98B-CD65-490D-83C6-0BFB6F10FA95}
DEFINE_GUID(MOUSEVPN_CALLOUT_BIND_V4,
    0x02b4a98b, 0xcd65, 0x490d, 0x83, 0xc6, 0x0b, 0xfb, 0x6f, 0x10, 0xfa, 0x95);
// {5E96782F-3FCB-441C-8D09-FEF5C16B00B0}
DEFINE_GUID(MOUSEVPN_CALLOUT_CONNECT_V6,
    0x5e96782f, 0x3fcb, 0x441c, 0x8d, 0x09, 0xfe, 0xf5, 0xc1, 0x6b, 0x00, 0xb0);
// {C61160B3-BE17-41EF-B7A6-2F669DA8CC96}
DEFINE_GUID(MOUSEVPN_CALLOUT_BIND_V6,
    0xc61160b3, 0xbe17, 0x41ef, 0xb7, 0xa6, 0x2f, 0x66, 0x9d, 0xa8, 0xcc, 0x96);

typedef struct MOUSEVPN_REDIRECT_CONTEXT {
    ADDRESS_FAMILY family;
    USHORT reserved;
    union {
        IN_ADDR ipv4;
        IN6_ADDR ipv6;
    } address;
} MOUSEVPN_REDIRECT_CONTEXT;
