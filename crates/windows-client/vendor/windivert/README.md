# Vendored WinDivert 2.2.2

Upstream: <https://github.com/basil00/WinDivert/releases/tag/v2.2.2>
Archive: `WinDivert-2.2.2-A.zip`, SHA-256
`63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15`

Files taken from the archive's `x64/` directory, unmodified:

| File | Origin |
| --- | --- |
| `WinDivert.dll` | `x64/WinDivert.dll` |
| `WinDivert64.sys` | `x64/WinDivert64.sys` |
| `windivert.h` | `include/windivert.h` (reference only, not compiled) |
| `LICENSE.txt` | archive root `LICENSE` |

## Why the driver loads without test signing

`WinDivert64.sys` carries two Authenticode signatures. The primary one is an
EV certificate; the second is the Microsoft attestation signature that the
kernel actually requires:

```
Signature Index: 1
    Issued to: Microsoft Windows Hardware Compatibility Publisher
    Issued by: Microsoft Windows Third Party Component CA 2014
```

Both signatures are timestamped (September 2022), so the expired signing
certificates do not invalidate them. Verify after any version bump:

```powershell
signtool verify /pa /all /v .\WinDivert64.sys
```

A build that reports only one signature must not ship — it would need test
signing on the end user's machine.

## Licensing

WinDivert is distributed under LGPL v3 or GPL v2, at our choice. MouseVPN takes
the **LGPL v3** option, which keeps our own sources closed. That choice imposes
three obligations, and the packaging depends on all of them:

1. **Ship these files unmodified, as separate files next to the executable.**
   They are deliberately *not* embedded with `include_bytes!` the way
   `vendor/wintun/wintun.dll` is. LGPL v3 requires that a user be able to
   substitute their own build of the library; a copy re-extracted from the
   executable on every launch would overwrite theirs.
2. Do not patch WinDivert itself. Modifications would have to be published
   under the LGPL.
3. Ship `LICENSE.txt` and credit WinDivert in the installer, with a pointer to
   the upstream sources above.
