# Randomized firmware validation

Draw seed: `18009606432315756635`. One release image per distinct target within each source. A target may represent a board, chip platform, product family or hardware component. Sources use different definitions. Downloads were made after the stratified random draw. Unavailable or mismatching downloads were retained in the ledger and excluded from both evaluations. No replacement draws.

The firmware was scanned from numeric paths. The baseline is commit c1733c8331c90c6819f8baf2fcec032aa792790f. Only development scans were examined before changes were frozen. Both versions were then evaluated on identical input bytes. Export success requires at least one emitted regular file with a checked SHA-256. Component slices were compared to source bytes, including reconstruction of discontiguous UF2 blocks. Format counts include generic containers (ZIP, TAR, gzip); identity counts indicate a nonempty board or supported-device field, not independently verified physical identity. Suites include catalogued OpenWrt hashes. No physical installation, boot, CVE assessment or encryption validation was part of this benchmark.

| Sample | Scanned | Format before / after | Identity before / after | Export before / after |
|---|---:|---:|---:|---:|
| development | 182 | 75 / 162 | 56 / 133 | 88 / 147 |
| holdout | 91 | 41 / 83 | 29 / 67 | 47 / 76 |
| all | 273 | 116 / 245 | 85 / 200 | 135 / 223 |

| Source | Eligible targets | Drawn | Scanned | Format after | Identity after | Export after |
|---|---:|---:|---:|---:|---:|---:|
| [OpenWrt](OpenWrt.jsonl) | 809 | 85 | 85 | 57 | 85 | 76 |
| [CircuitPython](CircuitPython.jsonl) | 311 | 90 | 88 | 88 | 86 | 88 |
| [OpenIPC](OpenIPC.jsonl) | 91 | 27 | 27 | 27 | 0 | 27 |
| [Rockbox](Rockbox.jsonl) | 50 | 32 | 32 | 32 | 29 | 32 |
| [LVFS](LVFS.jsonl) | 554 | 70 | 41 | 41 | 0 | 0 |

Sources: OpenWrt 24.10.0 profiles for ath79/generic, bcm53xx/generic, ipq40xx/generic, mediatek/filogic and ramips/mt7621; CircuitPython 9.2.8 board directories for raspberrypi, atmel-samd and nordic; OpenIPC NOR Lite/Ultimate release assets up to 32 MiB; Rockbox 3.15 player builds; LVFS stable metadata with a published cabinet SHA-256, capped at 64 MiB declared download size. The ledgers retain URLs and observed hashes for replay. Previously catalogued OpenWrt releases and the limited platform choices constrain generalization.

An additional receiver/printer spot check is reported separately. Smartphone and scanner coverage needs a separate sampling frame. CAB directory recognition in this revision does not extract firmware members.


### Follow-up sample outside the primary comparison

Eight MediaStar product pages were drawn from the publisher home page. Two receiver images were available before download access was interrupted. Both the Gazal Forever 10 Plus and Mini700 Max samples returned unknown with zero exported components. The other six were not scored. Both printer families in the Prusa Buddy 8.0.1 release were selected, with a random build per family. A separate follow-up BBF v2 reader identified MINI and XL and exported firmware code plus four resource records from each; all ten slices matched their source bytes. These two examples informed the reader and are not an independent holdout. No BBF result is included in the primary comparison.
