# xworm_extractor

Static config extractor for XWorm .NET payloads. The sample is parsed, never run.

## How it works

1. Reads the .NET metadata and collects every string in the `#US` heap.
2. Keeps the strings that could be AES ciphertext: valid Base64 that decodes to a multiple of 16 bytes.
3. Tries each heap string as the mutex and derives the key the way XWorm does:
   ```
   digest     = MD5(mutex)
   key[0:16]  = digest
   key[15:31] = digest        key[15] = digest[0], key[31] = 0
   value      = AES-256-ECB decrypt, PKCS7 unpad
   ```
   The candidate that decrypts the most settings is the mutex. Field names don't matter, so obfuscated builds work too.
4. Labels the values by format and by XWorm's field order: hosts, port, KEY, splitter, group, USB name, install folder and file name, Telegram token and chat ID, and clipper wallets (BTC, ETH, TRX, LTC).
5. Adds `c2_traffic_key_md5`, the MD5 of KEY, which is the AES key XWorm uses for C2 traffic. Useful for decrypting a PCAP.

## Usage

```bash
pip install -r requirements.txt
python xworm_extractor.py sample.exe
python xworm_extractor.py samples/ -r -o results.jsonl --only-ok
python xworm_extractor.py sample.exe --dump-strings
```

Exits with `0` if at least one config was extracted, otherwise `1`. With several files, a count per status is printed at the end.

Output for the campaign sample (`9ef39965...`):

```json
{
  "file": "stage3_payload.bin",
  "sha256": "9ef39965263531f35203eea0a1924181264cf6d7f3832d939cd532d5fad77a2d",
  "status": "ok",
  "family": "XWorm",
  "extractor_version": "1.1.0",
  "version": "7.1",
  "c2": ["109.248.150.234:1012"],
  "config": {
    "hosts": ["109.248.150.234"],
    "port": 1012,
    "group": "XWorm V7.1",
    "install_dir": "%AppData%",
    "aes_key": "<V7PV7PV7PV7PV7P>",
    "splitter": "<Xwormmm>",
    "usb_name": "USB.exe",
    "install_name": "bin.exe",
    "mutex": "aGO284VKfQVe8Vup",
    "c2_traffic_key_md5": "db33dfcb0f12980632b06186486e63bf"
  },
  "config_aes_key_hex": "c56dd1cefefcff04cb771a22da65c2c56dd1cefefcff04cb771a22da65c2b600",
  "decrypted_values": ["109.248.150.234", "1012", "<V7PV7PV7PV7PV7P>", "<Xwormmm>",
                       "XWorm V7.1", "USB.exe", "%AppData%", "bin.exe"],
  "unlabeled_values": []
}
```

## Status values

| Status | Meaning |
|---|---|
| `ok` | Config extracted |
| `no_config` | .NET with strings, but nothing decrypts. Packed, obfuscated, or not XWorm. |
| `dotnet_no_strings` | .NET, but the `#US` heap is missing or empty. The error lists which streams exist. |
| `not_dotnet` | Native PE, usually a loader or crypter |
| `not_pe` | Not a PE file |
| `error` | Read or parse error, see `error` |

## Tested samples

Payloads:

| SHA256 | Version | C2 |
|---|---|---|
| `9ef39965263531f35203eea0a1924181264cf6d7f3832d939cd532d5fad77a2d` | 7.1 | `109.248.150.234:1012`, matches the manual analysis |
| `3f980de6bd0581609105f594ba932e5e54a9eb1afac81d7543a3a4da8aac9a6e` | 5.4 | `188.212.158.75:7000` |
| `d00a97e1e2f4ba671f1377bfe7802cd76d04ddebf75a51c850c4711007b16418` | 7.4 | `13.140.42.128:7004`, plus BTC, ETH and TRX clipper wallets |
| `200088491d4bae1446a09224eeb946eab26512b2f18ef2872ba054493c3ac029` | 7.4 | `egym7md-64674.portmap.host:64674` |
| `6b116e502a393c4b6286dc50d7e66efda65612e0cce0441ac8e22745e1dd05ab` | 6.0 | `ppu8fagyc3.localto.net:2743` |
| `cce0be64fb1ee5622987669dcf7492a2f146e77c6af300787452f4d64bb3af67` | 5.6 | `33.tcp.cpolar.top:11914` |
| `3dd9f794833b29db94173ee707a300162e388cf75357e494e328954b5d61c650` | group `AGOSTO2` | `108.181.175.198:7000` |
| `c784971dffa317fcb27e9e47d68939b22871c0061e293921ca9c2591e3070ae8` | 3.0 | `watfcokhms.localto.net:8845` |
| `192dedbd5e3ee5c2d519506420db2a1982970337fa34fa205849108a7ae08635` | group `SLUMZICK v8.5` | `45.141.27.251:7777` |

Loaders and crypted builds labeled XWorm on MalwareBazaar and Triage. All were rejected with the right status:

| SHA256 | Status |
|---|---|
| `2b5f0c927f5436d8c04d58bb8c9fba470cbbf4ce23eacf2d65e336ca2bb59d97` | `not_dotnet` |
| `5387372b2ac54854b8e99201675221e3e477a924bc767b9cb247fb516c9ef4dc` | `not_dotnet` |
| `df0a8c4215b3b5e5d2dedfcb54cc487c98aaf8bfc8c6d4e5965aa677429b3792` | `not_dotnet` |
| `9fe26e83fc24dc5694b406705c80ab43875323157fb6b4d9d3511df83a76cc57` | `not_dotnet` |
| `3dd9a087a124f08ae4a29d420a2362544c8a0f32e1a9bdfb1b2b3fac1789d753` | `dotnet_no_strings` |
| `7c388bfc8638159a5bbff8d90462dd54e37d99beb6498028a023446bf2d4516c` | `dotnet_no_strings` |
| `553f13ad0daf5cc2897b177df386c40b12b83c581f7685131a52f30b48b37987` | `dotnet_no_strings` |
| `f1a75d5acaf8fa5a809bc814958cdd466d22aef012641f756e8bb16f04eb2556` | `dotnet_no_strings` |
| `ba3ae937bd1d826fe270ea22b138974749aef0401d1c51a746a4c5e7cc382db7` | `dotnet_no_strings` |
| `87f1b3971bb5b44a760fe934c32c9364d1b417fb253da60bee93bf5569f7dc15` | `no_config` |

## Limitations

- Needs the unpacked payload. Loaders and crypted builds have to be unpacked first, for example by dumping from memory with hollows_hunter.
- Labels come from value formats, so an unusual config may be labeled wrong. Every decrypted value is always in `decrypted_values`, and anything unlabeled is in `unlabeled_values`.
- `Sleep` is an integer field, not a string, so it isn't extracted.

## Tests

```bash
python -m unittest discover -s tests -v
```

Unit tests cover the key layout, the #US parser, labeling, and decryption of real strings from the V3.0 sample. The end-to-end tests compile a small C# program with a `Settings` class encrypted the same way XWorm does it, so no malware is needed. They need `csc.exe`, which ships with the .NET Framework on Windows.
