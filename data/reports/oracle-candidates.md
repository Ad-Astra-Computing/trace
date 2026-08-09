# Adaptation-oracle candidates

nixpkgs: `/home/agent/code/nixpkgs`
nixpkgs_ref: `nixpkgs`
total patches scanned: 252
wired: 189 / unwired: 63 (unwired = orphaned patch, no derivation applies it → not oracle-viable)

| classification | count |
|---|---|
| likely-adaptation | 160 |
| likely-verbatim | 90 |
| unknown | 2 |

## Ranked candidates (best-first)

| rank | score | cve_ids | package | wired | classification | files | hunks | +/- | signals | patch_path |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 184.36 | CVE-2021-45078 | binutils | yes | likely-adaptation | 1 | 3 | +43/-45 | adapted, version-target:apply to 2.35.2 | `pkgs/development/tools/misc/binutils/CVE-2021-45078.patch` |
| 2 | 148.94 | CVE-2019-8287 | tightvnc | yes | likely-adaptation | 1 | 1 | +1/-1 | adapted | `pkgs/tools/admin/tightvnc/1.3.10-CVE-2019-8287.patch` |
| 3 | 148.94 | CVE-2024-6387 | openssh | yes | likely-adaptation | 1 | 1 | +2/-0 | backport | `pkgs/tools/networking/openssh/openssh-9.6_p1-CVE-2024-6387.patch` |
| 4 | 148.85 | CVE-2019-11471 | libheif | yes | likely-adaptation | 1 | 1 | +5/-0 | adapted | `pkgs/development/libraries/libheif/1.4.0-CVE-2019-11471.patch` |
| 5 | 148.82 | CVE-2019-15678 | tightvnc | yes | likely-adaptation | 1 | 1 | +6/-0 | adapted | `pkgs/tools/admin/tightvnc/1.3.10-CVE-2019-15678.patch` |
| 6 | 148.79 | CVE-2019-15679 | tightvnc | yes | likely-adaptation | 1 | 1 | +6/-1 | adapted | `pkgs/tools/admin/tightvnc/1.3.10-CVE-2019-15679.patch` |
| 7 | 147.88 | CVE-2022-46908 | sqlite | yes | likely-adaptation | 1 | 2 | +2/-2 | adapted | `pkgs/development/libraries/sqlite/3.39.4-autoconf-CVE-2022-46908.patch` |
| 8 | 147.31 | CVE-2015-1283 | expat | yes | likely-adaptation | 1 | 2 | +21/-2 | modified | `pkgs/development/libraries/expat/CVE-2015-1283.patch` |
| 9 | 135.75 | CVE-2020-27619 | 2.7 | yes | likely-adaptation | 2 | 2 | +9/-16 | rebased | `pkgs/development/interpreters/python/cpython/2.7/CVE-2020-27619.patch` |
| 10 | 133.36 | CVE-2020-26116 | 2.7 | yes | likely-adaptation | 2 | 4 | +37/-1 | rebased | `pkgs/development/interpreters/python/cpython/2.7/CVE-2020-26116.patch` |
| 11 | 131.88 | CVE-2026-40347 | python-multipart | yes | likely-adaptation | 2 | 5 | +30/-24 | version-target:apply to 0.0.22 | `pkgs/development/python-modules/python-multipart/CVE-2026-40347-part-2.patch` |
| 12 | 131.24 | CVE-2020-8492 | 2.7 | yes | likely-adaptation | 2 | 3 | +101/-41 | rebased | `pkgs/development/interpreters/python/cpython/2.7/CVE-2020-8492.patch` |
| 13 | 131.16 | CVE-2024-34490 | maxima | yes | likely-adaptation | 3 | 5 | +20/-8 | version-target:adjusted to apply to 5.47.0 | `pkgs/applications/science/math/maxima/5.47.0-CVE-2024-34490.patch` |
| 14 | 130.21 | CVE-2021-22876 | curl | yes | likely-adaptation | 3 | 4 | +90/-3 | adapted | `pkgs/tools/networking/curl/7.74.0-CVE-2021-22876.patch` |
| 15 | 130.15 | CVE-2021-3177 | 2.7 | yes | likely-adaptation | 3 | 4 | +69/-26 | rebased | `pkgs/development/interpreters/python/cpython/2.7/CVE-2021-3177.patch` |
| 16 | 129.92 | CVE-2022-35920 | sanic | yes | likely-adaptation | 2 | 6 | +70/-16 | version-target:adjusted to apply to
v22.3.2 | `pkgs/development/python-modules/sanic/22.3.2-CVE-2022-35920.patch` |
| 17 | 129.37 | CVE-2015-7747 | audiofile | yes | likely-adaptation | 3 | 4 | +120/-1 | backport | `pkgs/development/libraries/audiofile/CVE-2015-7747.patch` |
| 18 | 128.98 | CVE-2024-3078 | qdrant | yes | likely-adaptation | 4 | 4 | +55/-29 | version-target:apply to 1.7.4 | `pkgs/servers/search/qdrant/1.7.4-CVE-2024-3078.patch` |
| 19 | 113.94 | CVE-2024-27318 | onnx | yes | likely-adaptation | 6 | 11 | +158/-94 | version-target:apply to 1.15.0 | `pkgs/development/python-modules/onnx/1.15.0-CVE-2024-27318.patch` |
| 20 | 108.97 | CVE-2009-1364 | libwmf | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/development/libraries/libwmf/CVE-2009-1364.patch` |
| 21 | 108.97 | CVE-2016-3189 | bzip2 | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/tools/compression/bzip2/CVE-2016-3189.patch` |
| 22 | 108.97 | CVE-2016-8858 | openssh | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/tools/networking/openssh/fix-CVE-2016-8858.patch` |
| 23 | 108.97 | CVE-2016-9102 | qemu | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/applications/virtualization/qemu/CVE-2016-9102.patch` |
| 24 | 108.97 | CVE-2019-19451 | dia | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/applications/graphics/dia/CVE-2019-19451.patch` |
| 25 | 108.97 | CVE-2021-45340 | libsixel | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/by-name/li/libsixel/fix-CVE-2021-45340.patch` |
| 26 | 108.97 | CVE-2022-28805 | lua-5 | yes | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/development/interpreters/lua-5/CVE-2022-28805.patch` |
| 27 | 108.94 | CVE-2013-6393 | libyaml | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/libyaml/cve-2013-6393_a.patch` |
| 28 | 108.94 | CVE-2014-2894 | qemu | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/applications/virtualization/qemu/cve-2014-2894.patch` |
| 29 | 108.94 | CVE-2014-5461 | lua-5 | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/interpreters/lua-5/CVE-2014-5461.patch` |
| 30 | 108.94 | CVE-2014-9157 | graphviz | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/tools/graphics/graphviz/cve-2014-9157.patch` |
| 31 | 108.94 | CVE-2015-3228 | ghostscript | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/misc/ghostscript/CVE-2015-3228.patch` |
| 32 | 108.94 | CVE-2015-3239 | libunwind | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/libunwind/cve-2015-3239.patch` |
| 33 | 108.94 | CVE-2016-3074 | gd | yes | likely-adaptation | 1 | 1 | +2/-0 | - | `pkgs/development/libraries/gd/CVE-2016-3074.patch` |
| 34 | 108.94 | CVE-2016-4912 | openslp | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/openslp/CVE-2016-4912.patch` |
| 35 | 108.94 | CVE-2017-11550, CVE-2017-11551 | libid3tag | yes | likely-adaptation | 1 | 1 | +2/-0 | - | `pkgs/development/libraries/libid3tag/CVE-2017-11550-and-CVE-2017-11551.patch` |
| 36 | 108.94 | CVE-2019-12900 | bzip2 | yes | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/tools/compression/bzip2/cve-2019-12900.patch` |
| 37 | 108.91 | CVE-2009-3560 | expat | yes | likely-adaptation | 1 | 1 | +3/-0 | - | `pkgs/development/libraries/expat/cve-2009-3560.patch` |
| 38 | 108.91 | CVE-2014-3618 | procmail | yes | likely-adaptation | 1 | 1 | +1/-2 | - | `pkgs/applications/misc/procmail/CVE-2014-3618.patch` |
| 39 | 108.91 | CVE-2016-9296 | p7zip | yes | likely-adaptation | 1 | 1 | +2/-1 | - | `pkgs/tools/archivers/p7zip/12-CVE-2016-9296.patch` |
| 40 | 108.91 | CVE-2020-24292 | freeimage | yes | likely-adaptation | 1 | 1 | +3/-0 | - | `pkgs/development/libraries/freeimage/CVE-2020-24292.patch` |
| 41 | 108.91 | CVE-2025-31162 | fig2dev | yes | likely-adaptation | 1 | 1 | +2/-1 | - | `pkgs/by-name/fi/fig2dev/CVE-2025-31162.patch` |
| 42 | 108.88 | CVE-2011-4919 | mpack | yes | likely-adaptation | 1 | 1 | +2/-2 | - | `pkgs/tools/networking/mpack/CVE-2011-4919.patch` |
| 43 | 108.88 | CVE-2012-0804 | cvs | yes | likely-adaptation | 1 | 1 | +2/-2 | - | `pkgs/applications/version-management/cvs/CVE-2012-0804.patch` |
| 44 | 108.88 | CVE-2014-8123 | antiword | yes | likely-adaptation | 1 | 1 | +4/-0 | - | `pkgs/applications/office/antiword/10_fix_buffer_overflow_wordole_c_CVE-2014-8123.patch` |
| 45 | 108.88 | CVE-2020-17525 | subversion | yes | likely-adaptation | 1 | 1 | +4/-0 | - | `pkgs/applications/version-management/subversion/CVE-2020-17525.patch` |
| 46 | 108.88 | CVE-2020-24293 | freeimage | yes | likely-adaptation | 1 | 1 | +4/-0 | - | `pkgs/development/libraries/freeimage/CVE-2020-24293.patch` |
| 47 | 108.88 | CVE-2021-40266 | freeimage | yes | likely-adaptation | 1 | 1 | +4/-0 | - | `pkgs/development/libraries/freeimage/CVE-2021-40266.patch` |
| 48 | 108.88 | CVE-2023-40889 | zbar | yes | likely-adaptation | 1 | 1 | +2/-2 | - | `pkgs/tools/graphics/zbar/0.23.92-CVE-2023-40889.patch` |
| 49 | 108.88 | CVE-2023-47995 | freeimage | yes | likely-adaptation | 1 | 1 | +4/-0 | - | `pkgs/development/libraries/freeimage/CVE-2023-47995.patch` |
| 50 | 108.85 | CVE-2015-4047 | ipsec-tools | yes | likely-adaptation | 1 | 1 | +5/-0 | - | `pkgs/os-specific/linux/ipsec-tools/CVE-2015-4047.patch` |
| 51 | 108.85 | CVE-2019-15680 | tightvnc | yes | likely-adaptation | 1 | 1 | +5/-0 | - | `pkgs/tools/admin/tightvnc/1.3.10-CVE-2019-15680.patch` |
| 52 | 108.85 | CVE-2021-40263 | freeimage | yes | likely-adaptation | 1 | 1 | +5/-0 | - | `pkgs/development/libraries/freeimage/CVE-2021-40263.patch` |
| 53 | 108.85 | CVE-2025-31344 | giflib | yes | likely-adaptation | 1 | 1 | +5/-0 | - | `pkgs/by-name/gi/giflib/CVE-2025-31344.patch` |
| 54 | 108.82 | CVE-2023-47997 | freeimage | yes | likely-adaptation | 1 | 1 | +6/-0 | - | `pkgs/development/libraries/freeimage/CVE-2023-47997.patch` |
| 55 | 108.79 | CVE-2013-6393 | libyaml | yes | likely-adaptation | 1 | 1 | +6/-1 | - | `pkgs/development/libraries/libyaml/cve-2013-6393_b.patch` |
| 56 | 108.79 | CVE-2016-1283 | pcre | yes | likely-adaptation | 1 | 1 | +6/-1 | - | `pkgs/development/libraries/pcre/CVE-2016-1283.patch` |
| 57 | 108.79 | CVE-2017-17969 | p7zip | yes | likely-adaptation | 1 | 1 | +6/-1 | - | `pkgs/tools/archivers/p7zip/13-CVE-2017-17969.patch` |
| 58 | 108.76 | CVE-2012-4426 | mcrypt | yes | likely-adaptation | 1 | 1 | +4/-4 | - | `pkgs/tools/misc/mcrypt/format-string_CVE-2012-4426.patch` |
| 59 | 108.76 | CVE-2016-6321 | gnutar | yes | likely-adaptation | 1 | 1 | +8/-0 | - | `pkgs/tools/archivers/gnutar/CVE-2016-6321.patch` |
| 60 | 108.76 | CVE-2017-8287 | freetype | yes | likely-adaptation | 1 | 1 | +8/-0 | - | `pkgs/development/libraries/freetype/cve-2017-8287.patch` |
| 61 | 108.73 | CVE-2017-8105 | freetype | yes | likely-adaptation | 1 | 1 | +9/-0 | - | `pkgs/development/libraries/freetype/cve-2017-8105.patch` |
| 62 | 108.73 | CVE-2021-33367 | freeimage | yes | likely-adaptation | 1 | 1 | +7/-2 | - | `pkgs/development/libraries/freeimage/CVE-2021-33367.patch` |
| 63 | 108.70 | CVE-2019-6706 | lua-5 | yes | likely-adaptation | 1 | 1 | +5/-5 | - | `pkgs/development/interpreters/lua-5/CVE-2019-6706.patch` |
| 64 | 108.70 | CVE-2025-60876 | busybox | yes | likely-adaptation | 1 | 1 | +9/-1 | - | `pkgs/os-specific/linux/busybox/CVE-2025-60876.patch` |
| 65 | 108.61 | CVE-2014-9913 | unzip | yes | likely-adaptation | 1 | 1 | +12/-1 | - | `pkgs/tools/archivers/unzip/CVE-2014-9913.patch` |
| 66 | 108.61 | CVE-2016-9844 | unzip | yes | likely-adaptation | 1 | 1 | +12/-1 | - | `pkgs/tools/archivers/unzip/CVE-2016-9844.patch` |
| 67 | 108.52 | CVE-2019-5786 | 5.12 | yes | likely-adaptation | 1 | 1 | +9/-7 | - | `pkgs/development/libraries/qt-5/5.12/qtwebengine-CVE-2019-5786.patch` |
| 68 | 107.92 | CVE-2019-15142 | djvulibre | yes | likely-adaptation | 1 | 1 | +19/-17 | - | `pkgs/applications/misc/djvulibre/CVE-2019-15142.patch` |
| 69 | 107.88 | CVE-2018-18065 | net-snmp | yes | likely-adaptation | 1 | 2 | +4/-0 | - | `pkgs/servers/monitoring/net-snmp/CVE-2018-18065.patch` |
| 70 | 107.88 | CVE-2019-15145 | djvulibre | yes | likely-adaptation | 1 | 2 | +2/-2 | - | `pkgs/applications/misc/djvulibre/CVE-2019-15145.patch` |
| 71 | 107.88 | CVE-2020-24295 | freeimage | yes | likely-adaptation | 1 | 2 | +4/-0 | - | `pkgs/development/libraries/freeimage/CVE-2020-24295.patch` |
| 72 | 107.88 | CVE-2020-7040 | store-backup | yes | likely-adaptation | 1 | 2 | +2/-2 | - | `pkgs/tools/backup/store-backup/CVE-2020-7040.patch` |
| 73 | 107.85 | CVE-2022-29360 | rainloop | yes | likely-adaptation | 1 | 2 | +3/-2 | - | `pkgs/servers/rainloop/fix-cve-2022-29360.patch` |
| 74 | 107.85 | CVE-2023-1972 | binutils | yes | likely-adaptation | 1 | 2 | +5/-0 | - | `pkgs/development/tools/misc/binutils/CVE-2023-1972.patch` |
| 75 | 107.82 | CVE-2017-15953 | bchunk | yes | likely-adaptation | 1 | 2 | +3/-3 | - | `pkgs/tools/cd-dvd/bchunk/CVE-2017-15953.patch` |
| 76 | 107.76 | CVE-2014-0172 | elfutils | yes | likely-adaptation | 1 | 2 | +7/-1 | - | `pkgs/development/tools/misc/elfutils/CVE-2014-0172.patch` |
| 77 | 107.76 | CVE-2017-15955 | bchunk | yes | likely-adaptation | 1 | 2 | +4/-4 | - | `pkgs/tools/cd-dvd/bchunk/CVE-2017-15955.patch` |
| 78 | 107.76 | CVE-2023-40890 | zbar | yes | likely-adaptation | 1 | 2 | +8/-0 | - | `pkgs/tools/graphics/zbar/0.23.92-CVE-2023-40890.patch` |
| 79 | 107.67 | CVE-2006-3376 | libwmf | yes | likely-adaptation | 1 | 2 | +9/-2 | - | `pkgs/development/libraries/libwmf/CVE-2006-3376.patch` |
| 80 | 107.25 | CVE-2021-3487 | binutils | yes | likely-adaptation | 1 | 2 | +19/-6 | - | `pkgs/development/tools/misc/binutils/CVE-2021-3487.patch` |
| 81 | 107.04 | CVE-2012-4552 | plib | yes | likely-adaptation | 1 | 2 | +14/-18 | - | `pkgs/development/libraries/plib/CVE-2012-4552.patch` |
| 82 | 106.82 | CVE-2017-12836 | cvs | yes | likely-adaptation | 1 | 3 | +5/-1 | - | `pkgs/applications/version-management/cvs/CVE-2017-12836.patch` |
| 83 | 106.70 | CVE-2018-18384 | unzip | yes | likely-adaptation | 1 | 3 | +5/-5 | - | `pkgs/tools/archivers/unzip/CVE-2018-18384.patch` |
| 84 | 106.67 | CVE-2013-6629 | libjpeg-turbo | yes | likely-adaptation | 1 | 3 | +10/-1 | - | `pkgs/development/libraries/libjpeg-turbo/libjpeg-turbo-1.3.0-CVE-2013-6629-and-6630.patch` |
| 85 | 106.64 | CVE-2025-6021 | libxml2 | yes | likely-adaptation | 1 | 3 | +9/-3 | - | `pkgs/development/libraries/libxml2/CVE-2025-6021.patch` |
| 86 | 106.61 | CVE-2026-7598 | libssh2 | yes | likely-adaptation | 1 | 3 | +12/-1 | - | `pkgs/by-name/li/libssh2/CVE-2026-7598.patch` |
| 87 | 106.39 | CVE-2019-15144 | djvulibre | yes | likely-adaptation | 1 | 1 | +48/-39 | - | `pkgs/applications/misc/djvulibre/CVE-2019-15144.patch` |
| 88 | 105.64 | CVE-2021-41581 | libressl | yes | likely-adaptation | 1 | 4 | +8/-4 | - | `pkgs/development/libraries/libressl/CVE-2021-41581.patch` |
| 89 | 105.52 | CVE-2023-4016 | procps-ng | yes | likely-adaptation | 1 | 4 | +12/-4 | - | `pkgs/os-specific/linux/procps-ng/v3-CVE-2023-4016.patch` |
| 90 | 103.80 | CVE-2025-3155 | yelp-xsl | yes | likely-adaptation | 1 | 5 | +38/-2 | - | `pkgs/by-name/ye/yelp-xsl/cve-2025-3155.patch` |
| 91 | 102.77 | CVE-2021-23336 | 2.7 | yes | likely-adaptation | 7 | 24 | +100/-41 | rebased | `pkgs/development/interpreters/python/cpython/2.7/CVE-2021-23336.patch` |
| 92 | 102.05 | CVE-2026-6893 | dracut | yes | likely-adaptation | 1 | 6 | +38/-27 | - | `pkgs/by-name/dr/dracut/CVE-2026-6893.patch` |
| 93 | 100.28 | CVE-2012-4527 | mcrypt | yes | likely-adaptation | 1 | 9 | +13/-11 | - | `pkgs/tools/misc/mcrypt/sprintf_CVE-2012-4527.patch` |
| 94 | 99.11 | CVE-2013-6393 | libyaml | yes | likely-adaptation | 1 | 9 | +55/-8 | - | `pkgs/development/libraries/libyaml/cve-2013-6393_c.patch` |
| 95 | 98.17 | CVE-2020-14315 | bsdiff | yes | likely-adaptation | 1 | 4 | +178/-83 | - | `pkgs/tools/compression/bsdiff/CVE-2020-14315.patch` |
| 96 | 96.38 | CVE-2019-18804 | djvulibre | yes | likely-adaptation | 2 | 2 | +2/-2 | - | `pkgs/applications/misc/djvulibre/CVE-2019-18804.patch` |
| 97 | 96.38 | CVE-2026-5160 | goshs | yes | likely-adaptation | 2 | 2 | +3/-1 | - | `pkgs/by-name/go/goshs/CVE-2026-5160.patch` |
| 98 | 96.29 | CVE-2016-2037 | cpio | yes | likely-adaptation | 2 | 2 | +6/-1 | - | `pkgs/tools/archivers/cpio/CVE-2016-2037-out-of-bounds-write.patch` |
| 99 | 96.26 | CVE-2019-15143 | djvulibre | yes | likely-adaptation | 2 | 2 | +5/-3 | - | `pkgs/applications/misc/djvulibre/CVE-2019-15143.patch` |
| 100 | 96.17 | CVE-2023-49083 | ceph | yes | likely-adaptation | 2 | 2 | +10/-1 | - | `pkgs/tools/filesystems/ceph/python-cryptography-Cherry-pick-fix-for-CVE-2023-49083-on-cryptography-40.patch` |
| 101 | 96.11 | CVE-2012-3368 | dtach | yes | likely-adaptation | 2 | 2 | +10/-3 | - | `pkgs/tools/misc/dtach/fix-CVE-2012-3368.patch` |
| 102 | 94.75 | CVE-2017-7186 | pcre | yes | likely-adaptation | 2 | 3 | +24/-1 | - | `pkgs/development/libraries/pcre/CVE-2017-7186.patch` |
| 103 | 93.81 | CVE-2024-41254 | litestream | yes | likely-adaptation | 2 | 4 | +20/-3 | - | `pkgs/by-name/li/litestream/fix-cve-2024-41254.patch` |
| 104 | 93.58 | CVE-2014-1912 | 3.2 | yes | likely-adaptation | 3 | 3 | +14/-0 | - | `pkgs/development/interpreters/python/3.2/CVE-2014-1912.patch` |
| 105 | 93.55 | CVE-2014-1912 | 2.7 | yes | likely-adaptation | 3 | 3 | +15/-0 | - | `pkgs/development/interpreters/python/2.7/CVE-2014-1912.patch` |
| 106 | 93.34 | CVE-2021-22901 | curl | yes | likely-adaptation | 13 | 22 | +172/-50 | modified | `pkgs/tools/networking/curl/CVE-2021-22901.patch` |
| 107 | 92.08 | CVE-2013-4276 | lcms | yes | likely-adaptation | 2 | 6 | +9/-5 | - | `pkgs/development/libraries/lcms/cve-2013-4276.patch` |
| 108 | 91.60 | CVE-2025-31163 | fig2dev | yes | likely-adaptation | 2 | 6 | +22/-8 | - | `pkgs/by-name/fi/fig2dev/CVE-2025-31163.patch` |
| 109 | 90.53 | CVE-2015-1419 | vsftpd | yes | likely-adaptation | 3 | 5 | +48/-1 | - | `pkgs/servers/ftp/vsftpd/CVE-2015-1419.patch` |
| 110 | 90.38 | CVE-2018-3836 | k2pdfopt | yes | likely-adaptation | 3 | 5 | +51/-3 | - | `pkgs/applications/misc/k2pdfopt/leptonica-CVE-2018-3836.patch` |
| 111 | 88.91 | CVE-2018-18751 | gettext | yes | likely-adaptation | 1 | 18 | +50/-53 | - | `pkgs/development/libraries/gettext/CVE-2018-18751-bison.patch` |
| 112 | 86.83 | CVE-2022-0529, CVE-2022-0530 | unzip | yes | likely-adaptation | 2 | 9 | +69/-20 | - | `pkgs/by-name/un/unzip/28-cve-2022-0529-and-cve-2022-0530.patch` |
| 113 | 85.95 | CVE-2025-3155 | yelp | yes | likely-adaptation | 5 | 7 | +33/-2 | - | `pkgs/by-name/ye/yelp/cve-2025-3155.patch` |
| 114 | 85.87 | CVE-2019-19917, CVE-2019-19918 | lout | yes | likely-adaptation | 4 | 9 | +15/-6 | - | `pkgs/tools/typesetting/lout/CVE-2019-19917-and-CVE-2019-19918.patch` |
| 115 | 85.85 | CVE-2021-22890 | curl | yes | likely-adaptation | 10 | 36 | +110/-45 | adapted | `pkgs/tools/networking/curl/7.74.0-CVE-2021-22890.patch` |
| 116 | 85.21 | CVE-2019-5544 | openslp | yes | likely-adaptation | 3 | 9 | +83/-10 | - | `pkgs/development/libraries/openslp/CVE-2019-5544.patch` |
| 117 | 84.88 | CVE-2017-14176 | bazaar | yes | likely-adaptation | 2 | 12 | +51/-3 | - | `pkgs/applications/version-management/bazaar/CVE-2017-14176.patch` |
| 118 | 84.44 | CVE-2016-10396 | ipsec-tools | yes | likely-adaptation | 4 | 8 | +71/-31 | - | `pkgs/os-specific/linux/ipsec-tools/CVE-2016-10396.patch` |
| 119 | 83.83 | CVE-2025-6170 | libxml2 | yes | likely-adaptation | 5 | 9 | +30/-9 | - | `pkgs/development/libraries/libxml2/CVE-2025-6170.patch` |
| 120 | 81.22 | CVE-2025-62516 | pods | yes | likely-adaptation | 2 | 15 | +37/-39 | - | `pkgs/by-name/po/pods/cve-2025-62516.patch` |
| 121 | 80.98 | CVE-2026-0989 | libxml2 | yes | likely-adaptation | 3 | 12 | +130/-4 | - | `pkgs/development/libraries/libxml2/2.13-CVE-2026-0989.patch` |
| 122 | 80.35 | CVE-2015-0848 | libwmf | yes | likely-adaptation | 3 | 15 | +40/-15 | - | `pkgs/development/libraries/libwmf/CVE-2015-0848+4588+4695+4696.patch` |
| 123 | 77.39 | CVE-2019-9232, CVE-2019-9325, CVE-2019-9371, CVE-2019-9433 | libvpx | yes | likely-adaptation | 7 | 11 | +57/-30 | - | `pkgs/development/libraries/libvpx/CVE-2019-9232.CVE-2019-9325.CVE-2019-9371.CVE-2019-9433.patch` |
| 124 | 61.19 | CVE-2019-14973 | libtiff | yes | likely-adaptation | 8 | 23 | +71/-106 | - | `pkgs/development/libraries/libtiff/CVE-2019-14973.patch` |
| 125 | 49.94 | CVE-2014-0150 | qemu | yes | unknown | 1 | 0 | +1/-1 | - | `pkgs/applications/virtualization/qemu/cve-2014-0150.patch` |
| 126 | 39.94 | CVE-2014-7169 | bash | yes | unknown | 0 | 0 | +2/-0 | - | `pkgs/shells/bash/cve-2014-7169.patch` |
| 127 | 8.94 | CVE-2015-1345 | gnugrep | yes | likely-verbatim | 1 | 1 | +2/-0 | - | `pkgs/tools/text/gnugrep/cve-2015-1345.patch` |
| 128 | 8.94 | CVE-2015-8325 | openssh | yes | likely-verbatim | 1 | 1 | +1/-1 | - | `pkgs/tools/networking/openssh/CVE-2015-8325.patch` |
| 129 | 8.94 | CVE-2019-20907 | 2.7 | yes | likely-verbatim | 1 | 1 | +2/-0 | - | `pkgs/development/interpreters/python/cpython/2.7/CVE-2019-20907.patch` |
| 130 | 8.94 | CVE-2021-22898 | curl | yes | likely-verbatim | 1 | 1 | +1/-1 | - | `pkgs/tools/networking/curl/CVE-2021-22898.patch` |
| 131 | 8.91 | CVE-2012-4409 | mcrypt | yes | likely-verbatim | 1 | 1 | +2/-1 | - | `pkgs/tools/misc/mcrypt/overflow_CVE-2012-4409.patch` |
| 132 | 8.91 | CVE-2015-6908 | openldap | yes | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/development/libraries/openldap/CVE-2015-6908.patch` |
| 133 | 8.91 | CVE-2018-6952 | gnupatch | yes | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/tools/text/gnupatch/CVE-2018-6952.patch` |
| 134 | 8.91 | CVE-2026-11850 | krb5 | yes | likely-verbatim | 1 | 1 | +3/-0 | - | `pkgs/by-name/kr/krb5/CVE-2026-11850.patch` |
| 135 | 8.91 | CVE-2026-39979 | jq | yes | likely-verbatim | 1 | 1 | +2/-1 | - | `pkgs/by-name/jq/jq/CVE-2026-39979.patch` |
| 136 | 8.91 | CVE-2026-6507 | dnsmasq | yes | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/by-name/dn/dnsmasq/CVE-2026-6507.patch` |
| 137 | 8.88 | CVE-2018-25032 | zlib | yes | likely-verbatim | 1 | 1 | +2/-2 | - | `pkgs/development/libraries/zlib/CVE-2018-25032-2.patch` |
| 138 | 8.88 | CVE-2018-6951 | gnupatch | yes | likely-verbatim | 1 | 1 | +2/-2 | - | `pkgs/tools/text/gnupatch/CVE-2018-6951.patch` |
| 139 | 8.88 | CVE-2021-22945 | curl | yes | likely-verbatim | 1 | 1 | +4/-0 | - | `pkgs/tools/networking/curl/CVE-2021-22945.patch` |
| 140 | 8.88 | CVE-2021-40633 | giflib | yes | likely-verbatim | 1 | 1 | +3/-1 | - | `pkgs/development/libraries/giflib/CVE-2021-40633.patch` |
| 141 | 8.85 | CVE-2013-0211 | libarchive | yes | likely-verbatim | 1 | 1 | +5/-0 | - | `pkgs/development/libraries/libarchive/CVE-2013-0211.patch` |
| 142 | 8.85 | CVE-2016-9842 | zlib | yes | likely-verbatim | 1 | 1 | +3/-2 | - | `pkgs/development/libraries/zlib/CVE-2016-9842.patch` |
| 143 | 8.85 | CVE-2022-37434 | zlib | yes | likely-verbatim | 1 | 1 | +3/-2 | - | `pkgs/development/libraries/zlib/CVE-2022-37434.patch` |
| 144 | 8.82 | CVE-2017-14502 | libarchive | yes | likely-verbatim | 1 | 1 | +5/-1 | - | `pkgs/development/libraries/libarchive/CVE-2017-14502.patch` |
| 145 | 8.79 | CVE-2026-41992 | gzip | yes | likely-verbatim | 1 | 1 | +6/-1 | - | `pkgs/tools/compression/gzip/CVE-2026-41992.patch` |
| 146 | 8.76 | CVE-2024-47081 | requests | yes | likely-verbatim | 1 | 1 | +1/-7 | - | `pkgs/development/python-modules/requests/CVE-2024-47081.patch` |
| 147 | 8.43 | CVE-2026-0992 | libxml2 | yes | likely-verbatim | 1 | 1 | +18/-1 | - | `pkgs/development/libraries/libxml2/2.13-CVE-2026-0992.patch` |
| 148 | 7.79 | CVE-2015-1283 | expat | yes | likely-verbatim | 1 | 2 | +4/-3 | - | `pkgs/development/libraries/expat/CVE-2015-1283-refix.patch` |
| 149 | 7.79 | CVE-2019-13638 | gnupatch | yes | likely-verbatim | 1 | 2 | +2/-5 | - | `pkgs/tools/text/gnupatch/CVE-2019-13638.patch` |
| 150 | 7.79 | CVE-2020-27617 | qemu | yes | likely-verbatim | 1 | 2 | +3/-4 | - | `pkgs/applications/virtualization/qemu/CVE-2020-27617.patch` |
| 151 | 7.79 | CVE-2026-40355, CVE-2026-40356 | krb5 | yes | likely-verbatim | 1 | 2 | +6/-1 | - | `pkgs/by-name/kr/krb5/CVE-2026-40355-and-CVE-2026-40356.patch` |
| 152 | 7.76 | CVE-2017-14166 | libarchive | yes | likely-verbatim | 1 | 2 | +7/-1 | - | `pkgs/development/libraries/libarchive/CVE-2017-14166.patch` |
| 153 | 7.76 | CVE-2017-16943 | exim | yes | likely-verbatim | 1 | 2 | +4/-4 | - | `pkgs/servers/mail/exim/cve-2017-16943.patch` |
| 154 | 7.67 | CVE-2026-32316 | jq | yes | likely-verbatim | 1 | 2 | +10/-1 | - | `pkgs/by-name/jq/jq/CVE-2026-32316.patch` |
| 155 | 7.61 | CVE-2014-2583 | pam | yes | likely-verbatim | 1 | 2 | +12/-1 | - | `pkgs/os-specific/linux/pam/CVE-2014-2583.patch` |
| 156 | 6.88 | CVE-2016-9843 | zlib | yes | likely-verbatim | 1 | 3 | +1/-3 | - | `pkgs/development/libraries/zlib/CVE-2016-9843.patch` |
| 157 | 6.73 | CVE-2023-38471 | avahi | yes | likely-verbatim | 1 | 3 | +6/-3 | - | `pkgs/development/libraries/avahi/CVE-2023-38471-2.patch` |
| 158 | 6.46 | CVE-2016-9840 | zlib | yes | likely-verbatim | 1 | 3 | +8/-10 | - | `pkgs/development/libraries/zlib/CVE-2016-9840.patch` |
| 159 | 5.37 | CVE-2026-33947 | jq | yes | likely-verbatim | 1 | 4 | +21/-0 | - | `pkgs/by-name/jq/jq/CVE-2026-33947.patch` |
| 160 | 3.62 | CVE-2024-8096 | curl | yes | likely-verbatim | 1 | 2 | +73/-73 | - | `pkgs/tools/networking/curl/CVE-2024-8096.patch` |
| 161 | -2.43 | CVE-2016-9841 | zlib | yes | likely-verbatim | 1 | 10 | +31/-50 | - | `pkgs/development/libraries/zlib/CVE-2016-9841.patch` |
| 162 | -3.71 | CVE-2026-56391 | coreutils | yes | likely-verbatim | 2 | 2 | +5/-2 | - | `pkgs/tools/misc/coreutils/CVE-2026-56391.patch` |
| 163 | -3.77 | CVE-2026-41991 | gzip | yes | likely-verbatim | 2 | 2 | +4/-5 | - | `pkgs/tools/compression/gzip/CVE-2026-41991.patch` |
| 164 | -3.83 | CVE-2021-4217 | unzip | yes | likely-verbatim | 2 | 2 | +9/-2 | - | `pkgs/by-name/un/unzip/CVE-2021-4217.patch` |
| 165 | -3.92 | CVE-2026-33948 | jq | yes | likely-verbatim | 2 | 2 | +7/-7 | - | `pkgs/by-name/jq/jq/CVE-2026-33948.patch` |
| 166 | -4.80 | CVE-2026-56392 | coreutils | yes | likely-verbatim | 2 | 3 | +9/-1 | - | `pkgs/tools/misc/coreutils/CVE-2026-56392.patch` |
| 167 | -5.76 | CVE-2024-41810 | twisted | yes | likely-verbatim | 2 | 3 | +39/-3 | - | `pkgs/development/python-modules/twisted/CVE-2024-41810.patch` |
| 168 | -5.83 | CVE-2013-0254 | 4.8 | yes | likely-verbatim | 2 | 4 | +5/-6 | - | `pkgs/development/libraries/qt-4.x/4.8/CVE-2013-0254.patch` |
| 169 | -5.86 | CVE-2021-22897 | curl | yes | likely-verbatim | 2 | 4 | +8/-4 | - | `pkgs/tools/networking/curl/CVE-2021-22897.patch` |
| 170 | -6.24 | CVE-2015-5073 | pcre | yes | likely-verbatim | 3 | 3 | +6/-2 | - | `pkgs/development/libraries/pcre/cve-2015-5073.patch` |
| 171 | -6.58 | CVE-2026-40164 | jq | yes | likely-verbatim | 2 | 4 | +34/-2 | - | `pkgs/by-name/jq/jq/CVE-2026-40164.patch` |
| 172 | -6.63 | CVE-2015-3210 | pcre | yes | likely-verbatim | 3 | 3 | +18/-3 | - | `pkgs/development/libraries/pcre/cve-2015-3210.patch` |
| 173 | -6.89 | CVE-2020-35448 | binutils | yes | likely-verbatim | 2 | 5 | +7/-6 | - | `pkgs/development/tools/misc/binutils/CVE-2020-35448.patch` |
| 174 | -8.22 | CVE-2023-38469 | avahi | yes | likely-verbatim | 2 | 6 | +22/-2 | - | `pkgs/development/libraries/avahi/CVE-2023-38469.patch` |
| 175 | -8.33 | CVE-2022-47016 | tmux | yes | likely-verbatim | 3 | 5 | +10/-1 | - | `pkgs/tools/misc/tmux/CVE-2022-47016.patch` |
| 176 | -9.31 | CVE-2019-13636 | gnupatch | yes | likely-verbatim | 2 | 7 | +21/-6 | - | `pkgs/tools/text/gnupatch/CVE-2019-13636.patch` |
| 177 | -11.12 | CVE-2025-5278 | coreutils | yes | likely-verbatim | 4 | 5 | +51/-3 | - | `pkgs/tools/misc/coreutils/CVE-2025-5278.patch` |
| 178 | -11.54 | CVE-2021-32490, CVE-2021-32491, CVE-2021-32492, CVE-2021-32493, CVE-2021-3500 | djvulibre | yes | likely-verbatim | 5 | 5 | +15/-3 | - | `pkgs/applications/misc/djvulibre/CVE-2021-3500+CVE-2021-32490+CVE-2021-32491+CVE-2021-32492+CVE-2021-32493.patch` |
| 179 | -13.02 | CVE-2018-1000156 | gnupatch | yes | likely-verbatim | 3 | 6 | +108/-26 | - | `pkgs/tools/text/gnupatch/CVE-2018-1000156.patch` |
| 180 | -14.94 | CVE-2024-41671 | twisted | yes | likely-verbatim | 2 | 9 | +126/-22 | - | `pkgs/development/python-modules/twisted/CVE-2024-41671.patch` |
| 181 | -15.40 | CVE-2019-17498 | libssh2 | yes | likely-verbatim | 5 | 7 | +33/-47 | - | `pkgs/development/libraries/libssh2/CVE-2019-17498.patch` |
| 182 | -16.91 | CVE-2015-1197 | libarchive | yes | likely-verbatim | 6 | 8 | +43/-4 | - | `pkgs/development/libraries/libarchive/CVE-2015-1197.patch` |
| 183 | -20.22 | CVE-2025-0938 | cpython | yes | likely-verbatim | 7 | 9 | +63/-11 | - | `pkgs/development/interpreters/python/cpython/CVE-2025-0938.patch` |
| 184 | -25.69 | CVE-2023-4863 | libwebp | yes | likely-verbatim | 4 | 16 | +129/-44 | - | `pkgs/development/libraries/libwebp/CVE-2023-4863.patch` |
| 185 | -27.50 | CVE-2018-25032 | zlib | yes | likely-verbatim | 3 | 20 | +79/-71 | - | `pkgs/development/libraries/zlib/CVE-2018-25032-1.patch` |
| 186 | -44.93 | CVE-2023-48795 | libssh2 | yes | likely-verbatim | 6 | 32 | +149/-32 | - | `pkgs/development/libraries/libssh2/CVE-2023-48795.patch` |
| 187 | -48.64 | CVE-2026-13482 | skypilot | yes | likely-verbatim | 17 | 22 | +61/-27 | - | `pkgs/by-name/sk/skypilot/CVE-2026-13482.patch` |
| 188 | -60.71 | CVE-2025-6020 | linux-pam | yes | likely-verbatim | 2 | 32 | +588/-319 | - | `pkgs/by-name/li/linux-pam/CVE-2025-6020.patch` |
| 189 | -65.16 | CVE-2016-0718 | expat | yes | likely-verbatim | 4 | 54 | +146/-76 | - | `pkgs/development/libraries/expat/CVE-2016-0718-v2-2-1.patch` |
| 190 | -851.12 | CVE-2019-19126 | glibc | **no** | likely-adaptation | 1 | 1 | +2/-2 | adapted | `pkgs/development/libraries/glibc/2.27-CVE-2019-19126.patch` |
| 191 | -851.15 | CVE-2021-43618 | gmp | **no** | likely-adaptation | 1 | 1 | +4/-1 | adapted | `pkgs/development/libraries/gmp/5.1.3-CVE-2021-43618.patch` |
| 192 | -851.27 | CVE-2023-49502 | ffmpeg | **no** | likely-adaptation | 1 | 1 | +5/-4 | version-target:adjusted to apply to 5.1.4 | `pkgs/development/libraries/ffmpeg/5.1.4-CVE-2023-49502.patch` |
| 193 | -864.82 | CVE-2020-25659 | cryptography | **no** | likely-adaptation | 2 | 2 | +12/-32 | backported | `pkgs/development/python-modules/cryptography/CVE-2020-25659.patch` |
| 194 | -891.03 | CVE-2024-56406 | perl | **no** | likely-adaptation | 1 | 1 | +1/-0 | - | `pkgs/development/interpreters/perl/CVE-2024-56406.patch` |
| 195 | -891.06 | CVE-2017-10140 | db | **no** | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/db/CVE-2017-10140-4.8-cwd-db_config.patch` |
| 196 | -891.06 | CVE-2017-10140 | db | **no** | likely-adaptation | 1 | 1 | +1/-1 | - | `pkgs/development/libraries/db/CVE-2017-10140-cwd-db_config.patch` |
| 197 | -891.15 | CVE-2014-0196 | kernel | **no** | likely-adaptation | 1 | 1 | +4/-1 | - | `pkgs/os-specific/linux/kernel/cve-2014-0196.patch` |
| 198 | -891.15 | CVE-2016-3075 | glibc | **no** | likely-adaptation | 1 | 1 | +1/-4 | - | `pkgs/development/libraries/glibc/cve-2016-3075.patch` |
| 199 | -891.15 | CVE-2021-43618 | gmp | **no** | likely-adaptation | 1 | 1 | +4/-1 | - | `pkgs/development/libraries/gmp/6.2.1-CVE-2021-43618.patch` |
| 200 | -891.21 | CVE-2026-8376 | perl | **no** | likely-adaptation | 1 | 1 | +7/-0 | - | `pkgs/development/interpreters/perl/CVE-2026-8376.patch` |
| 201 | -891.39 | CVE-2022-34903 | gnupg | **no** | likely-adaptation | 1 | 1 | +4/-9 | - | `pkgs/tools/security/gnupg/CVE-2022-34903-g10-fix-garbled-status-messages-in-NOTATION_DATA.patch` |
| 202 | -891.75 | CVE-2020-1752 | glibc | **no** | likely-adaptation | 1 | 1 | +13/-12 | - | `pkgs/development/libraries/glibc/2.30-cve-2020-1752.patch` |
| 203 | -892.09 | CVE-2013-2217 | python-modules | **no** | likely-adaptation | 1 | 2 | +2/-1 | - | `pkgs/development/python-modules/suds-0.4-CVE-2013-2217.patch` |
| 204 | -892.12 | CVE-2019-9959 | poppler | **no** | likely-adaptation | 1 | 2 | +2/-2 | - | `pkgs/development/libraries/poppler/0.61-CVE-2019-9959.patch` |
| 205 | -892.24 | CVE-2025-40928 | perl-modules | **no** | likely-adaptation | 1 | 2 | +4/-4 | - | `pkgs/development/perl-modules/JSON-XS-CVE-2025-40928.patch` |
| 206 | -892.45 | CVE-2014-5033 | files | **no** | likely-adaptation | 1 | 2 | +3/-12 | - | `pkgs/desktops/kde-4.12/files/kdelibs-cve-2014-5033.patch` |
| 207 | -892.45 | CVE-2014-5033 | files | **no** | likely-adaptation | 1 | 2 | +3/-12 | - | `pkgs/desktops/kde-4.14/files/kdelibs-cve-2014-5033.patch` |
| 208 | -892.60 | CVE-2013-4458 | 2.18 | **no** | likely-adaptation | 1 | 2 | +18/-2 | - | `pkgs/development/libraries/glibc/2.18/cve-2013-4458.patch` |
| 209 | -892.69 | CVE-2013-1914 | 2.17 | **no** | likely-adaptation | 1 | 2 | +21/-2 | - | `pkgs/development/libraries/glibc/2.17/cve-2013-1914.patch` |
| 210 | -892.78 | CVE-2016-8605 | guile | **no** | likely-adaptation | 1 | 2 | +11/-15 | - | `pkgs/development/interpreters/guile/CVE-2016-8605.patch` |
| 211 | -895.63 | CVE-2014-0004 | udisks | **no** | likely-adaptation | 1 | 5 | +15/-6 | - | `pkgs/os-specific/linux/udisks/cve-2014-0004.patch` |
| 212 | -896.31 | CVE-2014-5119 | 2.19 | **no** | likely-adaptation | 1 | 1 | +4/-173 | - | `pkgs/development/libraries/glibc/2.19/cve-2014-5119.patch` |
| 213 | -896.54 | CVE-2013-0242 | 2.17 | **no** | likely-adaptation | 1 | 6 | +9/-9 | - | `pkgs/development/libraries/glibc/2.17/cve-2013-0242.patch` |
| 214 | -896.90 | CVE-2016-3706 | glibc | **no** | likely-adaptation | 1 | 3 | +69/-61 | - | `pkgs/development/libraries/glibc/cve-2016-3706.patch` |
| 215 | -903.77 | CVE-2026-7381 | perl-modules | **no** | likely-adaptation | 2 | 2 | +8/-1 | - | `pkgs/development/perl-modules/Plack-xsendfile-disable-by-default-CVE-2026-7381.patch` |
| 216 | -906.10 | CVE-2013-0252 | boost | **no** | likely-adaptation | 2 | 4 | +20/-0 | - | `pkgs/development/libraries/boost/CVE-2013-0252.patch` |
| 217 | -906.63 | CVE-2013-4332 | 2.18 | **no** | likely-adaptation | 3 | 3 | +21/-0 | - | `pkgs/development/libraries/glibc/2.18/cve-2013-4332.patch` |
| 218 | -907.68 | CVE-2020-10029 | glibc | **no** | likely-adaptation | 3 | 3 | +55/-1 | - | `pkgs/development/libraries/glibc/2.31-cve-2020-10029.patch` |
| 219 | -912.14 | CVE-2014-0475 | 2.19 | **no** | likely-adaptation | 2 | 8 | +73/-15 | - | `pkgs/development/libraries/glibc/2.19/cve-2014-0475.patch` |
| 220 | -917.77 | CVE-2013-4184 | perl-modules | **no** | likely-adaptation | 4 | 10 | +6/-103 | - | `pkgs/development/perl-modules/Data-UUID-CVE-2013-4184.patch` |
| 221 | -920.77 | CVE-2016-1234 | glibc | **no** | likely-adaptation | 3 | 10 | +159/-100 | - | `pkgs/development/libraries/glibc/cve-2016-1234.patch` |
| 222 | -922.78 | CVE-2012-4412 | 2.18 | **no** | likely-adaptation | 1 | 5 | +514/-412 | - | `pkgs/development/libraries/glibc/2.18/cve-2012-4412+4424.patch` |
| 223 | -928.40 | CVE-2013-4237 | 2.18 | **no** | likely-adaptation | 8 | 14 | +96/-34 | - | `pkgs/development/libraries/glibc/2.18/cve-2013-4237.patch` |
| 224 | -932.26 | CVE-2013-4788 | 2.18 | **no** | likely-adaptation | 12 | 13 | +92/-0 | - | `pkgs/development/libraries/glibc/2.18/cve-2013-4788.patch` |
| 225 | -933.22 | CVE-2015-7547 | glibc | **no** | likely-adaptation | 3 | 19 | +309/-65 | - | `pkgs/development/libraries/glibc/cve-2015-7547.patch` |
| 226 | -991.06 | CVE-2016-0728 | kernel | **no** | likely-verbatim | 1 | 1 | +1/-1 | - | `pkgs/os-specific/linux/kernel/cve-2016-0728.patch` |
| 227 | -991.09 | CVE-2011-10007 | perl-modules | **no** | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/development/perl-modules/FileFindRule-CVE-2011-10007.patch` |
| 228 | -991.09 | CVE-2015-1781 | glibc | **no** | likely-verbatim | 1 | 1 | +2/-1 | - | `pkgs/development/libraries/glibc/cve-2015-1781.patch` |
| 229 | -991.09 | CVE-2026-42250 | patches | **no** | likely-verbatim | 1 | 1 | +1/-2 | - | `pkgs/tools/compression/bzip2/patches/CVE-2026-42250.patch` |
| 230 | -991.12 | CVE-2017-1000366 | glibc | **no** | likely-verbatim | 1 | 1 | +2/-2 | - | `pkgs/development/libraries/glibc/CVE-2017-1000366-rtld-LD_LIBRARY_PATH.patch` |
| 231 | -991.12 | CVE-2022-3996 | 3.0 | **no** | likely-verbatim | 1 | 1 | +0/-4 | - | `pkgs/development/libraries/openssl/3.0/CVE-2022-3996.patch` |
| 232 | -991.54 | CVE-2023-2975 | 3.0 | **no** | likely-verbatim | 1 | 1 | +11/-7 | - | `pkgs/development/libraries/openssl/3.0/CVE-2023-2975.patch` |
| 233 | -992.12 | CVE-2023-4807 | 1.1 | **no** | likely-verbatim | 1 | 2 | +2/-2 | - | `pkgs/development/libraries/openssl/1.1/CVE-2023-4807.patch` |
| 234 | -992.27 | CVE-2025-40929 | perl-modules | **no** | likely-verbatim | 1 | 2 | +4/-5 | - | `pkgs/development/perl-modules/Cpanel-JSON-XS-CVE-2025-40929.patch` |
| 235 | -992.89 | CVE-2024-5535 | 3.3 | **no** | likely-verbatim | 1 | 1 | +40/-23 | - | `pkgs/development/libraries/openssl/3.3/CVE-2024-5535.patch` |
| 236 | -994.18 | CVE-2013-4396 | xorg | **no** | likely-verbatim | 1 | 4 | +5/-1 | - | `pkgs/servers/x11/xorg/xorgserver-cve-2013-4396.patch` |
| 237 | -995.22 | CVE-2017-1000366 | glibc | **no** | likely-verbatim | 1 | 3 | +57/-17 | - | `pkgs/development/libraries/glibc/CVE-2017-1000366-rtld-LD_PRELOAD.patch` |
| 238 | -1002.45 | CVE-2017-1000366 | glibc | **no** | likely-verbatim | 1 | 9 | +99/-16 | - | `pkgs/development/libraries/glibc/CVE-2017-1000366-rtld-LD_AUDIT.patch` |
| 239 | -1003.89 | CVE-2024-12254 | 3.12 | **no** | likely-verbatim | 2 | 2 | +13/-0 | - | `pkgs/development/interpreters/python/cpython/3.12/CVE-2024-12254.patch` |
| 240 | -1004.71 | CVE-2018-11237 | glibc | **no** | likely-verbatim | 2 | 3 | +4/-3 | - | `pkgs/development/libraries/glibc/CVE-2018-11237.patch` |
| 241 | -1004.92 | CVE-2025-4575 | 3.5 | **no** | likely-verbatim | 2 | 3 | +12/-2 | - | `pkgs/development/libraries/openssl/3.5/CVE-2025-4575.patch` |
| 242 | -1005.21 | CVE-2016-9580, CVE-2016-9581 | openjpeg | **no** | likely-verbatim | 1 | 12 | +70/-37 | - | `pkgs/development/libraries/openjpeg/CVE-2016-9580-and-CVE-2016-9581.patch` |
| 243 | -1008.85 | CVE-2018-11236 | glibc | **no** | likely-verbatim | 3 | 3 | +92/-3 | - | `pkgs/development/libraries/glibc/CVE-2018-11236.patch` |
| 244 | -1009.66 | CVE-2014-8121 | glibc | **no** | likely-verbatim | 3 | 3 | +120/-2 | - | `pkgs/development/libraries/glibc/cve-2014-8121.patch` |
| 245 | -1018.17 | CVE-2022-3219 | gnupg | **no** | likely-verbatim | 4 | 11 | +68/-21 | - | `pkgs/tools/security/gnupg/CVE-2022-3219.patch` |
| 246 | -1023.77 | CVE-2024-27297 | 2_3 | **no** | likely-verbatim | 7 | 7 | +253/-6 | - | `pkgs/tools/package-management/nix/patches/2_3/CVE-2024-27297.patch` |
| 247 | -1026.15 | CVE-2024-27297 | 2_18 | **no** | likely-verbatim | 8 | 8 | +250/-5 | - | `pkgs/tools/package-management/nix/patches/2_18/CVE-2024-27297.patch` |
| 248 | -1028.92 | CVE-2024-27297 | 2_19 | **no** | likely-verbatim | 9 | 9 | +256/-8 | - | `pkgs/tools/package-management/nix/patches/2_19/CVE-2024-27297.patch` |
| 249 | -1039.07 | CVE-2025-40909 | perl | **no** | likely-verbatim | 12 | 16 | +28/-191 | - | `pkgs/development/interpreters/perl/CVE-2025-40909.patch` |
| 250 | -1039.19 | CVE-2025-4516 | 3.14 | **no** | likely-verbatim | 8 | 22 | +160/-63 | - | `pkgs/development/interpreters/python/cpython/3.14/CVE-2025-4516.patch` |
| 251 | -1124.11 | CVE-2025-4517 | 3.14 | **no** | likely-verbatim | 11 | 75 | +967/-170 | - | `pkgs/development/interpreters/python/cpython/3.14/CVE-2025-4517.patch` |
| 252 | -1218.04 | CVE-2025-46415 | patches | **no** | likely-verbatim | 57 | 99 | +813/-355 | - | `pkgs/tools/package-management/lix/patches/LIX_HEAD_CVE-2025-46415_46416.patch` |
