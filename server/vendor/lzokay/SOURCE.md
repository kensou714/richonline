# Vendored LZOkay

- Upstream: https://github.com/AxioDL/lzokay
- Fixed commit: `db2df1fcbebc2ed06c10f727f72567d40f06a2be`
- Source: https://github.com/AxioDL/lzokay/tree/db2df1fcbebc2ed06c10f727f72567d40f06a2be
- License: MIT, copyright (c) 2018 Jack Andersen; see the retained `LICENSE`.
- Retrieved on 2026-10-09 through GitHub's contents API at the fixed commit, decoded directly from its base64 response. The raw.githubusercontent.com endpoint failed with a transport connection reset.

Original upstream SHA-256 hashes before local changes:

| File | SHA-256 |
| --- | --- |
| LICENSE | 28933aedd9381e87e1fabb4491b00dfddd4f24ecac6adb7988fa1df7cf296813 |
| lzokay.hpp | 0a6165e6726f27c1abfc1b1bb0613b1a839f4285d5cd6108d62d63cc713645c7 |
| lzokay.cpp | 2f4ab24a24a65766f05e2aa60361c624d1a1b80e73164d2248300e0701d91e91 |

The algorithm is the upstream LZO1X implementation. Local safety changes in `lzokay.cpp` only:

- Read unaligned 16-bit values using `memcpy` instead of pointer casts.
- Compare remaining input/output sizes before advancing pointers.
- Stop zero-byte extension scanning at the input end, allowing the existing input check to reject truncation.
- Validate lookbehind distances as integers before subtracting from the output pointer.

Build this third-party source in its own library target, without applying the first-party `-Wconversion -Werror` policy to its existing implicit conversions. No external runtime or Python is required.
