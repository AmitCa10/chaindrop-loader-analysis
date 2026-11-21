# Static comparison of ChainDrop IDE and npm loaders

**Author:** [Amit Carmon](https://github.com/AmitCa10)

## Summary

This study compares two ChainDrop distribution paths:

- IDE/source-checkout files from `jaredwray/keyv` commit `d8c850c7800e514d582741a1f852b61122c31213`; and
- npm package files from `jaredwray/keyv` commit `ee2681a9b62f3637b0eb5133c36c864d3376cc5b`.

The loaders differ in size, SHA-256, obfuscation, and the filename used for the second stage. Nevertheless, they implement the same core behavior and launch byte-identical second-stage content.

This makes the pair a useful case for detection engineering: loader hashes and filenames are indicators, but they do not describe the whole malware family or its behavior.

## Provenance

| Artifact | Distribution path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| IDE `setup.mjs` | Source checkout | 11,017 | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` |
| npm `setup.mjs` | npm package | 29,918 | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` |
| IDE `math_init.js` | Source checkout | 727,680 | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` |
| npm `Math_Symbol.js` | npm package | 727,680 | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` |

All four local hashes match the values published by SafeDep. The second-stage files are also byte-identical to each other.

## Method

1. Retrieved exact files from the two public commits.
2. Computed hashes and byte sizes locally.
3. Statically decoded the npm loader's string array, RC4 variants, nested decoder aliases, quoted indices, and numeric constant objects in Python.
4. Compared installed-Bun behavior, platform selection, fallback extraction, cleanup, CI checks, and payload identity.
5. Asserted the results in `tools/compare_loaders.py` and saved them in `analysis/comparison.json`.

No JavaScript payload was executed.

## Finding 1: the loaders are behaviorally equivalent

The decoded artifacts share all of these properties:

| Property | IDE loader | npm loader |
| --- | --- | --- |
| Bun version | 1.3.13 | 1.3.13 |
| Installed Bun is used to execute the second stage | Yes | Yes |
| Platform and architecture selection | Present | Present |
| Internal ZIP parsing fallback | Present | Present |
| Temporary download cleanup | Present | Present |
| CI skip found | No | No |

The npm loader is about 2.72 times larger than the IDE loader and uses a substantially different obfuscation layout. That difference does not change the execution architecture.

Both loaders execute the second stage directly when a Bun command is available. Otherwise, they select a platform-specific Bun archive, download it from the official Bun release path, extract it, execute the payload, and clean up the temporary files.

## Finding 2: payload filenames differ while content is identical

The IDE loader names its target `math_init.js`; the npm loader uses `Math_Symbol.js`. The two targets have identical size and SHA-256 and were confirmed byte-for-byte equal locally.

A detection based only on one filename therefore misses the other distribution path. A detection based only on one loader hash misses the same chain in its alternate packaging.

## Defensive guidance

Use layered correlation rather than a single indicator:

1. Identify automatic execution entries such as IDE hooks and npm lifecycle scripts.
2. Resolve the referenced script rather than assuming a conventional filename.
3. Look for Bun runtime acquisition, platform-specific archive selection, second-stage execution, and cleanup behavior.
4. Use the second-stage hash as a separate artifact indicator, not as a substitute for behavior analysis.
5. Preserve source and distribution context so an IDE checkout and an npm installation are not treated as unrelated events.

The comparison also illustrates why a release's provenance is not proof of source safety. Provenance identifies a build path; it does not establish that the files built by that path were benign.

## Validation

`analysis/comparison.json` confirms:

- both published loader hashes match;
- both second-stage files are byte-identical;
- their published second-stage hash matches;
- all six shared behavior checks pass.

The comparison tool raises an assertion error if any of those expectations fails.

## Limitations

- No loader or second-stage payload was executed.
- The decoder is tailored to this npm loader's exact obfuscation structure and is not a general JavaScript deobfuscator.
- This study does not provide a full analysis of the second stage or live token-monitor behavior.
- Prior public reporting documented the loader and payload identities. This study's contribution is an independent decoder and a direct semantic comparison of the two distribution paths.

## Reproduce

From this directory:

```bash
python3 tools/decode_npm_loader.py \
  evidence/npm/setup.mjs \
  analysis/npm-decoded.js.txt

python3 tools/compare_loaders.py
```

The comparison prints JSON and raises an assertion error if the expected hashes, payload identity, or shared behavior does not hold.

## References

- [IDE hook commit](https://github.com/jaredwray/keyv/commit/d8c850c7800e514d582741a1f852b61122c31213)
- [npm payload commit](https://github.com/jaredwray/keyv/commit/ee2681a9b62f3637b0eb5133c36c864d3376cc5b)
- [SafeDep: keyv and cacheable compromise](https://safedep.io/blog/keyv-npm-supply-chain-compromise)
- [Elastic: ChainDrop / Shai-Hulud analysis](https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain)
