# Adaptation-oracle candidates

nixpkgs: `/nix/store/iqk1852cs7fy9ngi9svqg6kzg2irdgxn-dkxbk4sjs8p64vybnaby5mj3nl1rr31g-source`
nixpkgs_ref: `iqk1852cs7fy9ngi9svqg6kzg2irdgxn-dkxbk4sjs8p64vybnaby5mj3nl1rr31g-source`
total patches scanned: 49

| classification | count |
|---|---|
| likely-adaptation | 33 |
| likely-verbatim | 16 |
| unknown | 0 |

## Ranked candidates (best-first)

| rank | score | cve_ids | package | classification | files | hunks | +/- | signals | patch_path |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 131.88 | CVE-2026-40347 | python-multipart | likely-adaptation | 2 | 5 | +30/-24 | version-target:apply to 0.0.22 | `pkgs/development/python-modules/python-multipart/CVE-2026-40347-part-2.patch` |
| 2 | 131.16 | CVE-2024-34490 | maxima | likely-adaptation | 3 | 5 | +20/-8 | version-target:adjusted to apply to 5.47.0 | `pkgs/by-name/ma/maxima/5.47.0-CVE-2024-34490.patch` |
| 3 | 129.37 | CVE-2015-7747 | audiofile | likely-adaptation | 3 | 4 | +120/-1 | backport | `pkgs/by-name/au/audiofile/CVE-2015-7747.patch` |
| 4 | 108.97 | CVE-2022-28805 | lua-5 | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/development/interpreters/lua-5/CVE-2022-28805.patch` |
| 5 | 108.94 | CVE-2014-5461 | lua-5 | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/interpreters/lua-5/CVE-2014-5461.patch` |
| 6 | 108.94 | CVE-2016-4912 | openslp | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/by-name/op/openslp/CVE-2016-4912.patch` |
| 7 | 108.94 | CVE-2017-10140 | db | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/db/CVE-2017-10140-4.8-cwd-db_config.patch` |
| 8 | 108.94 | CVE-2017-10140 | db | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/db/CVE-2017-10140-cwd-db_config.patch` |
| 9 | 108.91 | CVE-2025-31162 | fig2dev | likely-adaptation | 1 | 1 | +2/-1 | - | `pkgs/by-name/fi/fig2dev/CVE-2025-31162.patch` |
| 10 | 108.88 | CVE-2014-8123 | antiword | likely-adaptation | 1 | 1 | +4/-0 | - | `pkgs/by-name/an/antiword/10_fix_buffer_overflow_wordole_c_CVE-2014-8123.patch` |
| 11 | 108.85 | CVE-2025-31344 | giflib | likely-adaptation | 1 | 1 | +5/-0 | - | `pkgs/by-name/gi/giflib/CVE-2025-31344.patch` |
| 12 | 108.79 | CVE-2026-8376 | perl | likely-adaptation | 1 | 1 | +7/-0 | - | `pkgs/development/interpreters/perl/CVE-2026-8376.patch` |
| 13 | 108.76 | CVE-2012-4426 | mcrypt | likely-adaptation | 1 | 1 | +4/-4 | - | `pkgs/by-name/mc/mcrypt/format-string_CVE-2012-4426.patch` |
| 14 | 108.70 | CVE-2025-60876 | busybox | likely-adaptation | 1 | 1 | +9/-1 | - | `pkgs/os-specific/linux/busybox/CVE-2025-60876.patch` |
| 15 | 108.61 | CVE-2014-9913 | unzip | likely-adaptation | 1 | 1 | +12/-1 | - | `pkgs/by-name/un/unzip/CVE-2014-9913.patch` |
| 16 | 108.61 | CVE-2016-9844 | unzip | likely-adaptation | 1 | 1 | +12/-1 | - | `pkgs/by-name/un/unzip/CVE-2016-9844.patch` |
| 17 | 107.88 | CVE-2020-7040 | storeBackup | likely-adaptation | 1 | 2 | +2/-2 | - | `pkgs/by-name/st/storeBackup/CVE-2020-7040.patch` |
| 18 | 107.85 | CVE-2022-29360 | rainloop | likely-adaptation | 1 | 2 | +3/-2 | - | `pkgs/servers/rainloop/fix-cve-2022-29360.patch` |
| 19 | 107.76 | CVE-2025-40928 | perl-modules | likely-adaptation | 1 | 2 | +4/-4 | - | `pkgs/development/perl-modules/JSON-XS-CVE-2025-40928.patch` |
| 20 | 107.22 | CVE-2016-8605 | guile | likely-adaptation | 1 | 2 | +11/-15 | - | `pkgs/development/interpreters/guile/CVE-2016-8605.patch` |
| 21 | 106.70 | CVE-2018-18384 | unzip | likely-adaptation | 1 | 3 | +5/-5 | - | `pkgs/by-name/un/unzip/CVE-2018-18384.patch` |
| 22 | 106.61 | CVE-2026-7598 | libssh2 | likely-adaptation | 1 | 3 | +12/-1 | - | `pkgs/by-name/li/libssh2/CVE-2026-7598.patch` |
| 23 | 100.28 | CVE-2012-4527 | mcrypt | likely-adaptation | 1 | 9 | +13/-11 | - | `pkgs/by-name/mc/mcrypt/sprintf_CVE-2012-4527.patch` |
| 24 | 98.17 | CVE-2020-14315 | bsdiff | likely-adaptation | 1 | 4 | +178/-83 | - | `pkgs/by-name/bs/bsdiff/CVE-2020-14315.patch` |
| 25 | 96.23 | CVE-2026-7381 | perl-modules | likely-adaptation | 2 | 2 | +8/-1 | - | `pkgs/development/perl-modules/Plack-xsendfile-disable-by-default-CVE-2026-7381.patch` |
| 26 | 92.08 | CVE-2013-4276 | lcms1 | likely-adaptation | 2 | 6 | +9/-5 | - | `pkgs/by-name/lc/lcms1/cve-2013-4276.patch` |
| 27 | 91.60 | CVE-2025-31163 | fig2dev | likely-adaptation | 2 | 6 | +22/-8 | - | `pkgs/by-name/fi/fig2dev/CVE-2025-31163.patch` |
| 28 | 91.36 | CVE-2026-13482 | skypilot | likely-adaptation | 17 | 22 | +61/-27 | context | `pkgs/by-name/sk/skypilot/CVE-2026-13482.patch` |
| 29 | 90.53 | CVE-2015-1419 | vsftpd | likely-adaptation | 3 | 5 | +48/-1 | - | `pkgs/by-name/vs/vsftpd/CVE-2015-1419.patch` |
| 30 | 86.83 | CVE-2022-0529, CVE-2022-0530 | unzip | likely-adaptation | 2 | 9 | +69/-20 | - | `pkgs/by-name/un/unzip/28-cve-2022-0529-and-cve-2022-0530.patch` |
| 31 | 85.21 | CVE-2019-5544 | openslp | likely-adaptation | 3 | 9 | +83/-10 | - | `pkgs/by-name/op/openslp/CVE-2019-5544.patch` |
| 32 | 82.23 | CVE-2013-4184 | perl-modules | likely-adaptation | 4 | 10 | +6/-103 | - | `pkgs/development/perl-modules/Data-UUID-CVE-2013-4184.patch` |
| 33 | 80.98 | CVE-2026-0989 | libxml2 | likely-adaptation | 3 | 12 | +130/-4 | - | `pkgs/development/libraries/libxml2/2.13-CVE-2026-0989.patch` |
| 34 | 8.91 | CVE-2011-10007 | perl-modules | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/development/perl-modules/FileFindRule-CVE-2011-10007.patch` |
| 35 | 8.91 | CVE-2012-4409 | mcrypt | likely-verbatim | 1 | 1 | +2/-1 | - | `pkgs/by-name/mc/mcrypt/overflow_CVE-2012-4409.patch` |
| 36 | 8.91 | CVE-2026-39979 | jq | likely-verbatim | 1 | 1 | +2/-1 | - | `pkgs/by-name/jq/jq/CVE-2026-39979.patch` |
| 37 | 8.91 | CVE-2026-42250 | bzip2 | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/tools/compression/bzip2/patches/CVE-2026-42250.patch` |
| 38 | 8.88 | CVE-2021-40633 | giflib | likely-verbatim | 1 | 1 | +3/-1 | - | `pkgs/by-name/gi/giflib/CVE-2021-40633.patch` |
| 39 | 8.76 | CVE-2024-47081 | requests | likely-verbatim | 1 | 1 | +1/-7 | - | `pkgs/development/python-modules/requests/CVE-2024-47081.patch` |
| 40 | 8.43 | CVE-2026-0992 | libxml2 | likely-verbatim | 1 | 1 | +18/-1 | - | `pkgs/development/libraries/libxml2/2.13-CVE-2026-0992.patch` |
| 41 | 7.79 | CVE-2026-40355, CVE-2026-40356 | krb5 | likely-verbatim | 1 | 2 | +6/-1 | - | `pkgs/by-name/kr/krb5/CVE-2026-40355-and-CVE-2026-40356.patch` |
| 42 | 7.73 | CVE-2025-40929 | perl-modules | likely-verbatim | 1 | 2 | +4/-5 | - | `pkgs/development/perl-modules/Cpanel-JSON-XS-CVE-2025-40929.patch` |
| 43 | 7.67 | CVE-2026-32316 | jq | likely-verbatim | 1 | 2 | +10/-1 | - | `pkgs/by-name/jq/jq/CVE-2026-32316.patch` |
| 44 | 5.37 | CVE-2026-33947 | jq | likely-verbatim | 1 | 4 | +21/-0 | - | `pkgs/by-name/jq/jq/CVE-2026-33947.patch` |
| 45 | -3.83 | CVE-2021-4217 | unzip | likely-verbatim | 2 | 2 | +9/-2 | - | `pkgs/by-name/un/unzip/CVE-2021-4217.patch` |
| 46 | -3.92 | CVE-2026-33948 | jq | likely-verbatim | 2 | 2 | +7/-7 | - | `pkgs/by-name/jq/jq/CVE-2026-33948.patch` |
| 47 | -6.58 | CVE-2026-40164 | jq | likely-verbatim | 2 | 4 | +34/-2 | - | `pkgs/by-name/jq/jq/CVE-2026-40164.patch` |
| 48 | -39.19 | CVE-2025-4516 | cpython | likely-verbatim | 8 | 22 | +160/-63 | - | `pkgs/development/interpreters/python/cpython/3.14/CVE-2025-4516.patch` |
| 49 | -60.71 | CVE-2025-6020 | linux-pam | likely-verbatim | 2 | 32 | +588/-319 | - | `pkgs/by-name/li/linux-pam/CVE-2025-6020.patch` |
