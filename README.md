# XWorm Analysis

Config extractor, YARA rules and IOCs from my analysis of XWorm, a .NET RAT sold as malware-as-a-service. The main case is a September 2026 phishing campaign that delivered XWorm V7.1 through a RAR, a JavaScript dropper and a PowerShell loader, ending in a hollowed `MSBuild.exe`.

Reports:
- [XWorm: from phishing email to RAT](https://artfuldodger10.github.io/posts/Xworm-Analysis/)
- [XWorm downloader: VBScript analysis](https://artfuldodger10.github.io/posts/XWorm-RAT-Malware-Analysis/)

## Contents

| Path | What it is |
|---|---|
| `tools/xworm_extractor/` | Static config extractor, tested on 9 payloads from V3.0 to V7.4 |
| `tools/mb_search.py` | Finds likely-unpacked XWorm payloads on MalwareBazaar |
| `detections/xworm.yar` | Three YARA rules: family, campaign payload, campaign loader. Maintained in [yara-rules](https://github.com/ArtfulDodger10/yara-rules/tree/main/rules/xworm) |
| `iocs/iocs.csv` | IOCs from both reports |
| `attack/xworm_layer.json` | ATT&CK Navigator layer for the V7.1 campaign |
| `reports/` | PDF copies of the reports |

## Key findings

**Config encryption.** Every setting is Base64 AES-256-ECB. The key is `MD5(mutex)` written into a 32-byte buffer twice, the second copy starting at offset 15, so `key[15]` holds `digest[0]` and the last byte stays zero. With that, any unpacked build can be decrypted without running it. The extractor tries every string in the #US heap as the mutex, so renamed fields don't matter.

**Delivery.** RAR attachment, then a JavaScript dropper (AES-256-CBC, ChaCha20 and XOR, gated behind two fake-activity counters), then a PowerShell loader with a custom base52 decoder, then XWorm loaded reflectively and hollowed into `MSBuild.exe`.

**C2.** Raw TCP to `109.248.150.234:1012`. Each frame is an ASCII length, a null byte, then AES-ECB ciphertext keyed with `MD5(KEY)`.

**Persistence.** A scheduled task every minute at highest privilege, an HKCU Run key, and a Startup folder shortcut that the malware keeps open so it can't be deleted.

## Across the builds

Running the extractor on payloads from V3.0 to V7.4 ([full list](tools/xworm_extractor/README.md#tested-samples)):

- The config scheme is the same in every version tested, so one extractor covers the family.
- Most operators keep the default traffic key `<123456789>` and splitter `<Xwormmm>`. The V7.4 builder defaults to `<V74PV74PV74PV74PV74P>` and `XWormClient.exe`. With a default key, captured C2 traffic can be decrypted without the sample.
- Several builds use tunneling services for C2 (`portmap.host`, `localto.net`, `cpolar.top`) rather than their own servers, which hides the operator's IP. DNS requests to these domains are worth hunting for.
- One V7.4 build carries clipper wallets for BTC, ETH and TRON, replacing addresses the victim copies.
- Group names such as `SLUMZICK v8.5` and `AGOSTO2` show the same builder being relabeled.

## Infection chain

```
Phishing email (ek@chaek.ru via mail.lpltd.ru)
  RAR attachment
    Stage 1: JS dropper (MB308992219AE.js)
      Stage 2: PowerShell loader (SysWOW64, -w h -nop -ep Bypass)
        Stage 3: XWorm V7.1 hollowed into MSBuild.exe
          C2: 109.248.150.234:1012/tcp
```

## Usage

```bash
cd tools/xworm_extractor
pip install -r requirements.txt
python xworm_extractor.py path/to/payload.exe
```

## Detection results

The rules are maintained in [yara-rules](https://github.com/ArtfulDodger10/yara-rules), together with rules for other families, a scanner and false-positive tests on 145,661 clean files. The copy here matches the version the results below were produced with.

Scanned with `yara64` against the 9 payloads, the loaders from the same sample set, and `C:\Windows\System32`.

| Rule | Payloads | Other files | System32 |
|---|---|---|---|
| XWorm_Payload_Generic | 9/9 (V3.0, 5.4, 5.6, 6.0, 7.1, 7.4, relabeled builds) | 0 loaders (the payload is encrypted inside them) | 0 hits |
| XWorm_Campaign_202609_Payload | 1/1 (`9ef39965...`) | 0 of the other 8 builds | 0 hits |
| XWorm_Campaign_202609_PS_Loader | not tested yet, the stage 2 script isn't in the set | - | 0 hits |

## Note

No live samples are stored here. Hashes are listed so the samples can be pulled from MalwareBazaar into an isolated lab.

MIT License
