#pragma once

#include <guiddef.h>

// Runtime callouts registered by the kernel driver and referenced by the
// helper's dynamic WFP management objects.
// {02B4A98B-CD65-490D-83C6-0BFB6F10FA95}
DEFINE_GUID(MOUSEVPN_CALLOUT_BIND_V4,
    0x02b4a98b, 0xcd65, 0x490d, 0x83, 0xc6, 0x0b, 0xfb, 0x6f, 0x10, 0xfa, 0x95);
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
