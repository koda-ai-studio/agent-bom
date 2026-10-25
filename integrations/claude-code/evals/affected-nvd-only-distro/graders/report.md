---
type: llm
---

PASS if the response says the Debian package php8.2-cli 8.2.29-1~deb12u1 in the scanned image is possibly affected (not confirmed), tells the user to verify it against Debian's (the distribution's) security advisory for php8.2, gives 8.2.35 only as the upstream fixed version for reference, identifies CVE-2026-109618 as a critical PHP remote code execution issue that NVD published and that is not known-exploited, and names what was scanned (the one image with 143 packages).
FAIL if it says the image is confirmed affected or vulnerable, calls the image or the machine safe or not affected, counts the package as a confirmed vulnerability, or describes assets that were not scanned as unaffected.
