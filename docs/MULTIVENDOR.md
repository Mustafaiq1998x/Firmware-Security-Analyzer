# Multi-vendor router firmware inspection

TRX v1, NETGEAR CHK with a TRX payload, and SEAMA use checked headers and payload bounds. CHK and TRX validate the inner CRC32; SEAMA checks its payload MD5. Structurally recognized images can be inspected even when their hash is absent from the catalog.

The bundled offline SHA-256 index identifies 1,173 specific OpenWrt 24.10.0 images across 809 target/device profiles from ath79/generic, bcm53xx/generic, ipq40xx/generic, mediatek/filogic and ramips/mt7621. A match records the upstream profiles.json URL in the evidence. This provides product and build identity independently of partition support. To regenerate the index, pass the five release profiles.json files to scripts/build_openwrt_index.py with --outdir src/fsa/assets/openwrt. Manufacturer releases can use different formats on the same hardware.

## Images exercised through the scanner

The exported component bytes were compared with the input at their declared offsets. Extracted archive members were checked against the manifest SHA-256.

| Image | Vendor | Outer format | Exported items | SHA-256 |
|---|---|---|---:|---|
| openwrt-24.10.0-ath79-generic-buffalo_wzr-hp-g300nh-rb-squashfs-factory.bin | Buffalo | unknown | 0 | 543a8eb006b9dbc6415c62269e9f3f5d6daa7f4a2ae278cda1f2f18a0f14f54b |
| openwrt-24.10.0-ath79-generic-buffalo_wzr-hp-g300nh-rb-squashfs-sysupgrade.bin | Buffalo | U-Boot legacy image | 2 | 8d3eaddb34e1323a99426e14ec911251c19878a5d816a410c2bac2194258b37f |
| openwrt-24.10.0-ath79-generic-dlink_dir-842-c1-squashfs-factory.bin | D-Link | SEAMA firmware | 1 | dc4a37a902f5656d035df8b2b37ce271787e31421cff1b66573e975ec48818eb |
| openwrt-24.10.0-ath79-generic-dlink_dir-842-c1-squashfs-sysupgrade.bin | D-Link | SEAMA firmware | 1 | 8240e847472ded7ec3885fcff4a1f71a9120fd892a9f3b8c53c199f0601baae4 |
| openwrt-24.10.0-bcm53xx-generic-asus_rt-ac68u-squashfs.trx | ASUS | Broadcom TRX v1 | 2 | 1075e7fcf2168215b4c5eb60a12c63d74fe239ea164156b7d11e318452bba0b6 |
| openwrt-24.10.0-bcm53xx-generic-netgear_r7000-squashfs.chk | NETGEAR | NETGEAR CHK with TRX v1 | 2 | db8c201ca30b1405527af37aa700aaa5348b4551e21595d4fc75b54ec0f1a34e |
| openwrt-24.10.0-ipq40xx-generic-linksys_ea6350v3-squashfs-factory.bin | Linksys | unknown | 1 | 42fa774a341d68e53e4e1784141eb461720ac514b810841a44d3cb0191a224f0 |
| openwrt-24.10.0-ipq40xx-generic-linksys_ea6350v3-squashfs-sysupgrade.bin | Linksys | TAR | 3 | 66bddb9cd0797101fd2166e17e8872e4c441c7ce6aea9a500a831e3462460559 |
| openwrt-24.10.0-ipq40xx-generic-zyxel_nbg6617-squashfs-factory.bin | Zyxel | unknown | 1 | 0cf2699af92b60b6064f340b5b3ed60f4dfe3b0586478a474ee12aeb34922049 |
| openwrt-24.10.0-ipq40xx-generic-zyxel_nbg6617-squashfs-sysupgrade.bin | Zyxel | TAR | 3 | d6308cc8943ccce749403687362aee5865294cbc219c56833fdc871c2d62ce5b |
| openwrt-24.10.0-mediatek-filogic-glinet_gl-mt6000-squashfs-factory.bin | GL.iNet | unknown | 1 | 556de22a36cfa996afbfe75ded641508001eb8a8fb1500ff49c58930e963984c |
| openwrt-24.10.0-mediatek-filogic-glinet_gl-mt6000-squashfs-sysupgrade.bin | GL.iNet | TAR | 3 | 9d919742a6f832b9f0d4073fa301dc78c9627acd7cab200acd703b6cf2351a82 |
| openwrt-24.10.0-ramips-mt7621-mikrotik_routerboard-750gr3-squashfs-sysupgrade.bin | MikroTik | unknown | 1 | 7df886cb6f29d827d8859a85dbf3fce35ab9690ca00be188a2c934030bdd80e3 |
| openwrt-24.10.0-ramips-mt7621-ubnt_edgerouter-x-squashfs-sysupgrade.bin | Ubiquiti | TAR | 3 | b2fb06ddac5b5777d23adac980113696cd047c61ea8423bb8fb2ec11e111c610 |
| openwrt-24.10.0-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin | Xiaomi | U-Boot legacy image | 2 | 13eca53abba2ceeb9e5fa546170930b0a9bcb22ec668a29b6937b9d1d7eb7d9a |
| stock-dir842.bin | D-Link | unknown | 0 | 50ff0338014842bfb6e179ca250c8a1389050776bad4be50c9b1d5f8503010ec |
| stock-r7000.chk | NETGEAR | NETGEAR CHK with TRX v1 | 2 | b28bf08e9d2c32d12d5a7bda45a93066d8bdf97274defc30f15fc36a437d02fb |

Stock inputs: [NETGEAR R7000](https://www.downloads.netgear.com/files/GDC/R7000/R7000-V1.0.11.136_10.2.120.zip), [D-Link DIR-842 Rev C](https://support.dlink.com/resource/PRODUCTS/DIR-842/REVC/DIR-842_REVC_FIRMWARE_v3.13B05.zip).
