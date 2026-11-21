# ChainDrop loader and second-stage comparison

Static comparison of two ChainDrop distribution paths: an IDE source checkout and an npm package.

The repository demonstrates that loaders with different hashes, sizes, obfuscation, and payload filenames implement the same behavior and launch a byte-identical second stage.

It contains:

- a static decoder for the npm loader's nested RC4 and string-array obfuscation;
- a semantic comparison tool for both loaders and both second-stage files;
- exact provenance hashes, validation, and a research report.

Raw and decoded malware are local-only and excluded through `.gitignore`.

## Reproduce

```bash
python3 tools/decode_npm_loader.py evidence/npm/setup.mjs analysis/npm-decoded.js.txt
python3 tools/compare_loaders.py
```

The comparison asserts published loader hashes, byte-identical second-stage content, and shared behavior. See `analysis/comparison.json` and `report.md`.
