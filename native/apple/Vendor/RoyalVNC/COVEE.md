# RoyalVNCKit in Covee

Source: <https://github.com/royalapplications/royalvnc>, commit `92d4427c73817d8f849bb289ff190aa4b40c44ea` (release 1.1.0). The upstream repository was archived in September 2026, so Covee keeps this copy. License: MIT, in `LICENSE`.

Covee uses it for screen sharing in the iPhone and iPad app. On a Mac, Covee opens macOS Screen Sharing instead.

## What differs from upstream

- `Package.swift` builds a static library for Apple platforms only. Upstream's library is dynamic, and Xcode then inferred that the iPhone app depends on the Mac app, which shares the name Covee.
- `Sources` holds only `RoyalVNCKit`, `RoyalVNCKitC`, `d3des` and `Z`, which links the system's zlib. The bundled zlib for Windows and the demos are left out.
- The JPEG and PNG packages are not used. Upstream needs them only on Linux, Windows and Android; on Apple platforms the Tight encoding decodes with ImageIO.
- CryptoSwift is pinned to the commit that upstream's release resolved, `a59b4d91ebb22011656c830f874fe7152e183a57` on royalapplications/CryptoSwift.

The Swift and C sources are unchanged.
