# Adaptation-oracle candidates

nixpkgs: `/nix/store/iqk1852cs7fy9ngi9svqg6kzg2irdgxn-dkxbk4sjs8p64vybnaby5mj3nl1rr31g-source`
nixpkgs_ref: `iqk1852cs7fy9ngi9svqg6kzg2irdgxn-dkxbk4sjs8p64vybnaby5mj3nl1rr31g-source`
total patches scanned: 49
wired: 37 / unwired: 12 (unwired = orphaned patch, no derivation applies it → not oracle-viable)

| classification | count |
|---|---|
| likely-adaptation | 32 |
| likely-verbatim | 17 |
| unknown | 0 |

## Ranked candidates (best-first)

| rank | score | cve_ids | package | wired | classification | files | hunks | +/- | signals | patch_path |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 131.16 | CVE-2024-34490 | maxima | yes | likely-adaptation | 3 | 5 | +20/-8 | version-target:adjusted to apply to 5.47.0 | `pkgs/by-name/ma/maxima/5.47.0-CVE-2024-34490.patch` |
| 2 | 129.37 | CVE-2015-7747 | audiofile | yes | likely-adaptation | 3 | 4 | +120/-1 | backport | `pkgs/by-name/au/audiofile/CVE-2015-7747.patch` |
| 3 | 108.97 | CVE-2022-28805 | lua-5 | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/development/interpreters/lua-5/CVE-2022-28805.patch` |
| 4 | 108.94 | CVE-2014-5461 | lua-5 | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/interpreters/lua-5/CVE-2014-5461.patch` |
| 5 | 108.94 | CVE-2016-4912 | openslp | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/by-name/op/openslp/CVE-2016-4912.patch` |
| 6 | 108.91 | CVE-2025-31162 | fig2dev | yes | likely-adaptation | 1 | 1 | +2/-1 | - | `pkgs/by-name/fi/fig2dev/CVE-2025-31162.patch` |
| 7 | 108.88 | CVE-2014-8123 | antiword | yes | likely-adaptation | 1 | 1 | +4/-0 | - | `pkgs/by-name/an/antiword/10_fix_buffer_overflow_wordole_c_CVE-2014-8123.patch` |
| 8 | 108.85 | CVE-2025-31344 | giflib | yes | likely-adaptation | 1 | 1 | +5/-0 | - | `pkgs/by-name/gi/giflib/CVE-2025-31344.patch` |
| 9 | 108.79 | CVE-2026-8376 | perl | yes | likely-adaptation | 1 | 1 | +7/-0 | - | `pkgs/development/interpreters/perl/CVE-2026-8376.patch` |
| 10 | 108.76 | CVE-2012-4426 | mcrypt | yes | likely-adaptation | 1 | 1 | +4/-4 | - | `pkgs/by-name/mc/mcrypt/format-string_CVE-2012-4426.patch` |
| 11 | 108.70 | CVE-2025-60876 | busybox | yes | likely-adaptation | 1 | 1 | +9/-1 | - | `pkgs/os-specific/linux/busybox/CVE-2025-60876.patch` |
| 12 | 108.61 | CVE-2014-9913 | unzip | yes | likely-adaptation | 1 | 1 | +12/-1 | - | `pkgs/by-name/un/unzip/CVE-2014-9913.patch` |
| 13 | 108.61 | CVE-2016-9844 | unzip | yes | likely-adaptation | 1 | 1 | +12/-1 | - | `pkgs/by-name/un/unzip/CVE-2016-9844.patch` |
| 14 | 107.88 | CVE-2020-7040 | storeBackup | yes | likely-adaptation | 1 | 2 | +2/-2 | - | `pkgs/by-name/st/storeBackup/CVE-2020-7040.patch` |
| 15 | 107.85 | CVE-2022-29360 | rainloop | yes | likely-adaptation | 1 | 2 | +3/-2 | - | `pkgs/servers/rainloop/fix-cve-2022-29360.patch` |
| 16 | 106.70 | CVE-2018-18384 | unzip | yes | likely-adaptation | 1 | 3 | +5/-5 | - | `pkgs/by-name/un/unzip/CVE-2018-18384.patch` |
| 17 | 106.61 | CVE-2026-7598 | libssh2 | yes | likely-adaptation | 1 | 3 | +12/-1 | - | `pkgs/by-name/li/libssh2/CVE-2026-7598.patch` |
| 18 | 100.28 | CVE-2012-4527 | mcrypt | yes | likely-adaptation | 1 | 9 | +13/-11 | - | `pkgs/by-name/mc/mcrypt/sprintf_CVE-2012-4527.patch` |
| 19 | 98.17 | CVE-2020-14315 | bsdiff | yes | likely-adaptation | 1 | 4 | +178/-83 | - | `pkgs/by-name/bs/bsdiff/CVE-2020-14315.patch` |
| 20 | 92.08 | CVE-2013-4276 | lcms1 | yes | likely-adaptation | 2 | 6 | +9/-5 | - | `pkgs/by-name/lc/lcms1/cve-2013-4276.patch` |
| 21 | 91.60 | CVE-2025-31163 | fig2dev | yes | likely-adaptation | 2 | 6 | +22/-8 | - | `pkgs/by-name/fi/fig2dev/CVE-2025-31163.patch` |
| 22 | 90.53 | CVE-2015-1419 | vsftpd | yes | likely-adaptation | 3 | 5 | +48/-1 | - | `pkgs/by-name/vs/vsftpd/CVE-2015-1419.patch` |
| 23 | 86.83 | CVE-2022-0529, CVE-2022-0530 | unzip | yes | likely-adaptation | 2 | 9 | +69/-20 | - | `pkgs/by-name/un/unzip/28-cve-2022-0529-and-cve-2022-0530.patch` |
| 24 | 85.21 | CVE-2019-5544 | openslp | yes | likely-adaptation | 3 | 9 | +83/-10 | - | `pkgs/by-name/op/openslp/CVE-2019-5544.patch` |
| 25 | 80.98 | CVE-2026-0989 | libxml2 | yes | likely-adaptation | 3 | 12 | +130/-4 | - | `pkgs/development/libraries/libxml2/2.13-CVE-2026-0989.patch` |
| 26 | 8.91 | CVE-2012-4409 | mcrypt | yes | likely-verbatim | 1 | 1 | +2/-1 | - | `pkgs/by-name/mc/mcrypt/overflow_CVE-2012-4409.patch` |
| 27 | 8.91 | CVE-2026-39979 | jq | yes | likely-verbatim | 1 | 1 | +2/-1 | - | `pkgs/by-name/jq/jq/CVE-2026-39979.patch` |
| 28 | 8.91 | CVE-2026-42250 | bzip2 | yes | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/tools/compression/bzip2/patches/CVE-2026-42250.patch` |
| 29 | 8.88 | CVE-2021-40633 | giflib | yes | likely-verbatim | 1 | 1 | +3/-1 | - | `pkgs/by-name/gi/giflib/CVE-2021-40633.patch` |
| 30 | 8.43 | CVE-2026-0992 | libxml2 | yes | likely-verbatim | 1 | 1 | +18/-1 | - | `pkgs/development/libraries/libxml2/2.13-CVE-2026-0992.patch` |
| 31 | 7.79 | CVE-2026-40355, CVE-2026-40356 | krb5 | yes | likely-verbatim | 1 | 2 | +6/-1 | - | `pkgs/by-name/kr/krb5/CVE-2026-40355-and-CVE-2026-40356.patch` |
| 32 | 7.67 | CVE-2026-32316 | jq | yes | likely-verbatim | 1 | 2 | +10/-1 | - | `pkgs/by-name/jq/jq/CVE-2026-32316.patch` |
| 33 | 5.37 | CVE-2026-33947 | jq | yes | likely-verbatim | 1 | 4 | +21/-0 | - | `pkgs/by-name/jq/jq/CVE-2026-33947.patch` |
| 34 | -3.83 | CVE-2021-4217 | unzip | yes | likely-verbatim | 2 | 2 | +9/-2 | - | `pkgs/by-name/un/unzip/CVE-2021-4217.patch` |
| 35 | -3.92 | CVE-2026-33948 | jq | yes | likely-verbatim | 2 | 2 | +7/-7 | - | `pkgs/by-name/jq/jq/CVE-2026-33948.patch` |
| 36 | -6.58 | CVE-2026-40164 | jq | yes | likely-verbatim | 2 | 4 | +34/-2 | - | `pkgs/by-name/jq/jq/CVE-2026-40164.patch` |
| 37 | -48.64 | CVE-2026-13482 | skypilot | yes | likely-verbatim | 17 | 22 | +61/-27 | - | `pkgs/by-name/sk/skypilot/CVE-2026-13482.patch` |
| 38 | -868.12 | CVE-2026-40347 | python-multipart | **no** | likely-adaptation | 2 | 5 | +30/-24 | version-target:apply to 0.0.22 | `pkgs/development/python-modules/python-multipart/CVE-2026-40347-part-2.patch` |
| 39 | -891.06 | CVE-2017-10140 | db | **no** | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/db/CVE-2017-10140-4.8-cwd-db_config.patch` |
| 40 | -891.06 | CVE-2017-10140 | db | **no** | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/db/CVE-2017-10140-cwd-db_config.patch` |
| 41 | -892.24 | CVE-2025-40928 | perl-modules | **no** | likely-adaptation | 1 | 2 | +4/-4 | - | `pkgs/development/perl-modules/JSON-XS-CVE-2025-40928.patch` |
| 42 | -892.78 | CVE-2016-8605 | guile | **no** | likely-adaptation | 1 | 2 | +11/-15 | - | `pkgs/development/interpreters/guile/CVE-2016-8605.patch` |
| 43 | -903.77 | CVE-2026-7381 | perl-modules | **no** | likely-adaptation | 2 | 2 | +8/-1 | - | `pkgs/development/perl-modules/Plack-xsendfile-disable-by-default-CVE-2026-7381.patch` |
| 44 | -917.77 | CVE-2013-4184 | perl-modules | **no** | likely-adaptation | 4 | 10 | +6/-103 | - | `pkgs/development/perl-modules/Data-UUID-CVE-2013-4184.patch` |
| 45 | -991.09 | CVE-2011-10007 | perl-modules | **no** | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/development/perl-modules/FileFindRule-CVE-2011-10007.patch` |
| 46 | -991.24 | CVE-2024-47081 | requests | **no** | likely-verbatim | 1 | 1 | +1/-7 | - | `pkgs/development/python-modules/requests/CVE-2024-47081.patch` |
| 47 | -992.27 | CVE-2025-40929 | perl-modules | **no** | likely-verbatim | 1 | 2 | +4/-5 | - | `pkgs/development/perl-modules/Cpanel-JSON-XS-CVE-2025-40929.patch` |
| 48 | -1039.19 | CVE-2025-4516 | cpython | **no** | likely-verbatim | 8 | 22 | +160/-63 | - | `pkgs/development/interpreters/python/cpython/3.14/CVE-2025-4516.patch` |
| 49 | -1060.71 | CVE-2025-6020 | linux-pam | **no** | likely-verbatim | 2 | 32 | +588/-319 | - | `pkgs/by-name/li/linux-pam/CVE-2025-6020.patch` |
