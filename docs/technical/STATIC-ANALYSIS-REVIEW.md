# Static-analysis security review

*Scope: defences against a **static** analyst — someone holding the APK/AAB who never runs it.
Dynamic analysis, Frida, `/proc/self/maps`, memory dumping, the session-key-in-memory window and
the Chow/BGE white-box ceiling are all deliberately out of scope. They are known, documented in
[`HARDENING.md`](./HARDENING.md) and [`../SECURITY.md`](../SECURITY.md), and unchanged by this
review.*

This takes the project on its own stated terms — *"anti-static-analysis obfuscation, not
cryptographic protection"* — and asks one question:

> Against an analyst who has the APK and never runs it, how much does sopack actually cost them?

Every finding below was **reproduced against real shipped artifacts in this repo**
(`output/vsa-encrypted.apk`, `output/app-release.apk`, `output/t4-chacha.apk`,
`artifacts/vsa-encrypted.aab`, `out/bundle/stubs/*`), not derived from reading source.

**Outcome.** The cryptographic core is sound and the documentation is unusually candid. But three
of the seven findings **bypass the crypto rather than break it**, and one shipped security claim
did not describe the artifact it labelled.

---

## What the design gets right

Stated first because it shapes everything below, and because these must not be regressed:

- **The `wbaes` default is architecturally sound.** `provision.py` seals a **fresh** KEK per pack
  (`secrets.token_hex(16)`, `secrets.randbits(64)`) and gives each target its own session key.
  There is no cross-app key reuse, so the universal-unpacker attack that destroys `chacha20`
  (S2) **does not carry to the default mode**. This is the single most important structural
  property in the project, and it holds.
- **Pack-time self-verification is used as a hardening control**, not merely a correctness check:
  `_self_verify` asserts the `SOPK` needle is absent from output, `_self_verify_wbaes` byte-scans
  the output for KEK/session-key material. Verified — no `SOPK` in any packed library.
- **The docs pre-reject the wrong fixes with real reasons** (section-header stripping breaks
  bionic on-device; `DT_INIT_ARRAY` hijack is reverted by relocations; bulk white-box is
  unusably slow). Every recommendation here was cross-checked against that rejected list.
- **ZIP timestamp normalisation** and the **helper strip** — both driven by a real external
  static-analysis report, both verified effective in shipped artifacts.

---

## Findings

| # | Severity | Finding | Bypasses the crypto? | Status |
|---|---|---|---|---|
| S1 | **Critical** | Cross-ABI cleartext: 20 of 21 protected libraries ship unencrypted in the same APK | Yes — entirely | Reported, not closed (accepted risk) |
| S2 | **Critical** | `chacha20`/`xor` has a universal unpacker needing **zero** reverse engineering | Yes — key is a build constant | Warned; polymorphic stub is the durable fix |
| S3 | **High** | O-MVLL did not cover sopack's own code, but `MANIFEST.txt` said it did | Mislabelled control | **Fixed** |
| S4 | **High** | The freestanding stub — which holds the whole recipe — is unobfuscated | Enables S2 | Deferred to the polymorphic stub |
| S5 | Medium | A tracing helper narrating the protocol in plaintext reached a real output APK | Yes, when triggered | Hardened |
| S6 | Medium | Target inventory published in the ZIP listing; constant helper size | Targeting aid | Open (low priority) |
| S7 | Low | Gratuitous literals: log strings, `WHITEN_NONCE`, NDK build-id, libsodium strings | Fingerprinting | Partly fixed |

---

## S1 — Cross-ABI cleartext bypass  **[Critical]**

`stubs.DEFAULT_ABIS = ("arm64-v8a",)`. Every other ABI passes through verbatim. Measured on the
real shipped `output/vsa-encrypted.apk`:

```
  arm64-v8a       24 app libs,  22 sopack artifacts -> PROTECTED
  armeabi-v7a     23 app libs,   0 sopack artifacts -> CLEARTEXT
  x86             13 app libs,   0 sopack artifacts -> CLEARTEXT
  x86_64          15 app libs,   0 sopack artifacts -> CLEARTEXT

  protected on arm64: 21
  of those, ALSO shipped CLEARTEXT in another ABI in the SAME APK: 20
```

Including every library the encryption exists to protect: `libpki.so`, `libzfcrypto.so`,
`libsecurefileio.so`, `libidliveface.so`, `libchecks.so`, `libloadTA.so`, `libapp.so`.

**Under a strictly static threat model this is not a partial gap — it is a complete bypass at
zero cost.** The analyst does not attack the white-box, the whitening, or the stub. They open
`lib/armeabi-v7a/` in the same file and read a full, symbol-bearing, source-equivalent build of
the identical code. Cost: one `unzip`.

[`IMPROVEMENTS.md`](./IMPROVEMENTS.md) §4 named this "the single largest gap" but framed the gate
as *"a decision about whether the emulator and x86_64-device install base matters."* **That
framing is wrong, and is why it stayed open.** The exposure has nothing to do with who *runs*
x86_64 — the cleartext copy is in the shipped file regardless of what executes it. A static
analyst never runs anything.

**Disposition: accepted risk, deliberately not remediated.** Closing it means protecting every
ABI (a per-ABI provider and KEK, plus fixing the stub path's unconditional 16 KB check — see
[`PAGE-ALIGNMENT.md`](./PAGE-ALIGNMENT.md) §7) or dropping ABIs from the container. Both are the
operator's call, not the packer's. The severity stays Critical: the finding is unchanged by the
decision not to fix it.

**What shipped instead:** `apk.find_cross_abi_cleartext()` detects it on every pack, the CLI
prints a `BYPASS:` block naming each library and where its cleartext copy is, and
`report.json` carries `cross_abi_cleartext` (with the count in `index.jsonl`). The exposure is
now measured rather than invisible.

### Reproduce

```bash
python3 - <<'EOF'
import sys, zipfile; sys.path.insert(0, '.')
from sopack.apk import find_cross_abi_cleartext
from sopack import container
z = zipfile.ZipFile('output/vsa-encrypted.apk')
ents = [i.filename for i in z.infolist()]
prot = [e for e in ents if e.startswith('lib/arm64-v8a/') and e.endswith('.so')
        and not e.split('/')[-1].startswith('libsopk_')
        and 'lib/arm64-v8a/libsopk_rt_' + e.split('/')[-1] in ents]
r = find_cross_abi_cleartext(ents, prot, container.APK)
print(f"protected: {len(prot)}   with a cleartext counterpart: {len(r)}")
EOF
```

---

## S2 — `chacha20`/`xor`: a universal unpacker needing no reverse engineering  **[Critical]**

The docs concede the ceiling: *"an analyst reverses the stub **once** and has a universal offline
unpacker."* The finding is that **no reverse engineering is required at all.**

The whitening key is `whiten_key(blob[decinfo_off-1024 : decinfo_off])` — a checksum over stub
code bytes. Those bytes are **constant across every packed app** for a given sopack build:
measured, the first **6,585 bytes** of the appended segment are byte-for-byte identical in every
packed library. The whitening key is therefore a **precomputable global constant**, not a
per-app secret.

Verified end to end against `output/t4-chacha.apk`:

```
universal whitening key: b6598d8658a292d0bdd65829cd7e89bc90b93a20fba8ee838862e4662f915f7e

libchecks.so: stub@0x7000  magic=b'SOPK' version=2  cipher=1  text_size=9536
libzfcore.so: stub@0x14000 magic=b'SOPK' version=2  cipher=1  text_size=47176
```

Decrypting `.text` with the recovered key yields valid aarch64:

```
0:  d503245f   bti c
4:  d503201f   nop
8:  1007ea20   adr x0, 0xfd4c
c:  14002e18   b   0xb86c
```

About 25 lines of Python, seconds to run, no disassembler opened. Critically,
**`magic == b'SOPK'` is a self-verifying 32-bit oracle**: a small brute-force over (record
offset, span offset, span length) discovers the whole scheme with no source at all.

### The v2 whitening replaced one fixed signature with another

Because the keystream is constant, *any decinfo field whose plaintext is constant has constant
ciphertext*. Verified identical across two different libraries in different apps:

```
  magic||version ct : 63a1c28dd10f75ee   (fixed 8-byte tag at decinfo_off)
  cipher_id ct      : 2f2513a5           (differs by ONE BIT between xor and chacha20
                                          -> the cipher choice is disclosed at rest)
  reserved[40] tail : 80df3c771b9bd5dd7c46028aff60b985...  (fixed 40-byte run, identical)
```

`grep SOPK` is dead, but a 48-byte fixed-offset needle replaces it exactly. What the whitening
*does* genuinely buy is real and should not be dismissed: the key and nonce bytes (offsets
40–88) are masked at rest. The mistake is treating that as removing the signature.
[`HARDENING.md`](./HARDENING.md) Method 1 has been amended accordingly.

### Why the obvious fixes do not work

The stub must recompute the key from bytes it possesses, and its bytes are constant. **No change
of hash function, salt, or span helps.** Per-pack *data* randomisation is pre-rejected in
[`ARCHITECTURE.md`](./ARCHITECTURE.md) §9e for the same reason. Only **per-pack code diversity**
produces per-app keys — see S4.

`wbaes` (the default) is immune: a fresh KEK per pack means no constant to precompute. sopack now
warns on every non-`wbaes` pack.

---

## S3 — O-MVLL did not cover sopack's own code, but the manifest said it did  **[High]**  — FIXED

`build_wbaes.sh` passed `$OMVLL_ARG` to exactly one command: WBC's `build_android.sh`, which
builds the vendored `libwbcrypto.a`. Neither `link_provider()` nor `link_skeleton()` passed any
plugin flag. So O-MVLL obfuscated the **vendored dependency**, while sopack's own glue —
`stub/sopk_wb.c` (region scan, passphrase de-whitening, the `wbc_open`/`wbc_unwrap_key`
sequence) and **all** of `stub/sopk_rt.c` (the decrypt-and-place dance) — was plain `-O2` output.

Confirmed by disassembling `sopk_wb_k` from a bundle whose `MANIFEST.txt` read
`provider-obfuscation: omvll`:

```
24f90: cbz  x1, ...          ; straight-line argument validation
24f98: cmp  x2, #0x30        ; 48 = WRAPPED_KEY_BYTES
24fa0: cmp  x4, #0x20        ; 32 = SESSION_KEY_BYTES
24fa8: cmp  w0, #0x3         ; region version 3
24fdc: bl   pthread_mutex_lock@plt
25004: bl   dl_iterate_phdr@plt
25018: cmp  w21, #0x400      ; 1024 = WHITEN_SPAN
```

No flattening, no opaque predicates, no string encryption. The protocol is legible.

**The severity was the mislabelling, not the missing pass.** `install.sh` surfaced the field as a
property of `libsopk_wb.so` — *"the artifact whose static-analysis resistance matters most"* —
but the field described the archive. A control that reports itself present when it is absent is
worse than a known gap: it stops anyone from looking. [`WBAES.md`](./WBAES.md) Phase 4 warned a
*manual* builder about exactly this; the automated path did not implement the warning.

**Fixed.** `link_provider()`/`link_skeleton()` now take `-fpass-plugin` plus `-Wl,-z,muldefs`,
driven by `stub/omvll_config_wb.py` (sopack's own policy — WBC's config names `vm.cpp`,
`trusted_storage.cpp` and would match nothing here, producing a silent no-op). `MANIFEST.txt`
splits the claim into `provider-obfuscation` / `helper-obfuscation` / `wbc-obfuscation` and
records `omvll-version` + `omvll-sha256`.

Most importantly, the claim is now **checkable**: `scripts/check_obfuscated.sh` measures the
artifact and `build_wbaes.sh` refuses a build that claims obfuscation it cannot demonstrate.

---

## S4 — The freestanding stub is entirely unobfuscated  **[High]**

`grep -i "omvll|mllvm|fpass-plugin"` over `stub/build_stubs.sh` returns nothing. In `chacha20`
mode the complete de-obfuscation recipe ships as plain, byte-identical code in every app. This
is what makes S2 "no RE required" rather than merely "reverse once".

**This is not what [`ARCHITECTURE.md`](./ARCHITECTURE.md) §9e rejected.** §9e rejects a *per-pack
recompiled polymorphic* stub on the grounds that it needs the toolchain at pack time. A
build-time-only O-MVLL pass keeps the prebuilt-blob model intact — but it does not break the
ceiling, since the blob stays constant.

**The real fix already exists, unmerged.** Branch `obfuscate-polymorphic-stub` (`dbb2311`, also
on `origin`) recompiles the stub per pack through O-MVLL with a fresh seed, so *"two packs of
the same lib differ in ~85-90% of stub bytes, yet each is reproducible from its seed."* It scopes
control-flow flattening + MBA + control-flow-breaking to `sopk_entry` and `sopk_chacha20_apply`,
and enables **only the relocation-free pass set**, determined empirically against
`build_stubs.sh`'s guards. At that byte divergence it genuinely breaks the ceiling — the one
thing in the repo's history that makes "reverse once, unpack everything" false.

---

## S5 — A tracing helper reached a real output APK  **[Medium]**

`output/app-release.apk` ships thin helpers with `DT_NEEDED liblog.so`, an imported
`__android_log_print`, the plaintext logcat tag `sopk_rt`, and **the whole protocol as English
format strings**:

```
region: target='%.*s' text_rva=0x%llx size=%llu
decrypted '%.*s' .text (%llu bytes) at 0x%lx - OK
sopk_wb_k failed (provider reason %d)
no metadata region found in self
timing '%.*s': wb=%.1fms copy=%.1fms decrypt=%.1fms place=%.1fms total=%.1fms
```

A narrated design document inside the shipped artifact — precisely the leak class
[`HARDENING.md`](./HARDENING.md) Method 5 was created to close after an external report
*"reconstructed the entire design in about an hour."*

**Scope check, and it limits the severity: this is isolated, not systemic.** The release path is
clean — `output/vsa-encrypted.apk` and `artifacts/vsa-encrypted.aab` both show no tracing. The
`_emit_helper` guard works. The issue is that `logging.allow-helper-log: true` is a single
boolean that disables it, and it demonstrably travelled into a real output APK once.

---

## S6 — The file listing publishes the target inventory  **[Medium]**

`_helper_soname_for` emits `libsopk_rt_<target>.so`, deterministically. The ZIP listing alone —
before parsing a single ELF — yields the vendor's own list of what it considered worth
protecting:

```
libsopk_rt_libpki.so, libsopk_rt_libzfcrypto.so, libsopk_rt_libsecurefileio.so,
libsopk_rt_libidliveface.so, libsopk_rt_libloadTA.so, libsopk_rt_libchecks.so, ...
```

Every thin helper is exactly **22,544 bytes**, another one-line signature.

[`HARDENING.md`](./HARDENING.md) argues renaming "buys an analyst-minute, not security", and for
*detection* that is right — the structural fingerprint is irremovable. But this is not detection,
it is **target selection**, and combined with S1 it is a shopping list pointing at the cleartext
counterparts one directory over.

---

## S7 — Gratuitous literals  **[Low]**

**The stub's 14 staged log strings ship in every `chacha20`-packed library.** They are gated only
by a *runtime* flag bit in decinfo, never compiled out. `stub_log.h`'s claim that when logging is
off "it is invisible" is true of logcat, not of `strings`. Verified in a packed `libchecks.so`:

```
H:native .text decrypted OK      A:entry      C:mmap ok=      D:decrypt done first8=
E:mremap ok=                     F:mprotect FAILED ret=       /dev/socket/logdw
```

`H:native .text decrypted OK` is a self-describing packer confession in cleartext in every packed
app — a strictly larger leak than the `sopack` tag that Method 4 went to the trouble of
XOR-obfuscating.

| Needle | Where | Note |
|---|---|---|
| `9e3779b97f4a7c15f1357aed039d2c1a` | every `chacha20` target | `WHITEN_NONCE` verbatim, adjacent to the XOR-obfuscated tag — a fixed 22-byte run |
| 14 staged log strings | every `chacha20` target | runtime-gated, not compiled out |
| `expand 32-byte k` | stub, helper, provider | ChaCha20 sigma, **immediately adjacent** to the 8-byte build marker in `.rodata` — a two-for-one signature |
| `.note.android.ident` → `r29`, `14206865` | helper + provider | exact NDK build fingerprint; survives strip (`SHF_ALLOC`) |
| `$argon2id`, `[LibsodiumDRG`, `cxa_demangle.cpp` | provider | identifies the white-box as libsodium-based; the demangler is dead RTTI weight |
| `SRTT` region fields | every helper | `text_rva`, `text_size`, target soname — all plaintext |

The **build markers must stay** ([`WBAES.md`](./WBAES.md) §8 — the stale-skeleton guard is a
byte-scan and being recognisable is its job).

---

## Repo hygiene — clean

`out/`, `output/`, `test_apks/`, `vendor/`, `artifacts/` and `*.apk` are gitignored; only four
binaries are tracked (three stub blobs and one test fixture) and no secrets. The tracked stub
blobs *are* the S2 signature, but they are recoverable from any shipped APK anyway, so
committing them changes nothing material.

---

## A note on how the obfuscation gate was calibrated

`scripts/check_obfuscated.sh` exists because of S3: a claim that cannot be checked eventually
lies. Its threshold was **measured, not assumed**, and the first attempt was wrong in an
instructive way.

Building one function with and without O-MVLL (NDK r26d + O-MVLL 1.6.0, flattening +
control-flow-breaking + MBA):

```
plain        32 instructions,   4 conditional branches
obfuscated  441 instructions,  11 conditional branches
```

Instruction count grew **13.8x**; conditional branches only **2.75x**, and branch *density* fell
(12.5% → 2.5%) because flattening dispatches through computed branches. A gate thresholded on
branch count — the intuitive choice — would have been close to useless.

Two further measurements forced the final design:

- **A symbol's `st_size` is not a reliable measure.** O-MVLL outlines the body into a sibling:
  `sopk_wb_k` went 128 → 56 bytes plus a new `sopk_wb_k.1` of 1708. Measured naively, the
  obfuscated function looks *smaller*.
- **Those siblings are LOCAL symbols**, so `--strip-all` deletes them. The provider can only be
  checked *before* stripping.

Hence two modes: `--mode symbol` sums the `sopk_wb_k` family pre-strip (the provider's whole
`.text` is no substitute — 75,602 of its ~75,738 instructions are vendored libwbcrypto), and
`--mode text` counts the thin helper's whole `.text`, which works stripped because the helper
links no white-box and is therefore 100% sopack's own code (measured plain: 613 instructions).

Exit 2 means "cannot tell" and is **never** treated as a pass.
