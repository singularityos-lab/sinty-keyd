# Contributing to sinty-keyd

## Quick Start

```bash
git clone https://github.com/singularityos-lab/sinty-keyd
cd sinty-keyd
go build ./...
go test ./...
```

## Guidelines

- Keep changes small and tested. Anything that touches the Key header, the
  wrapped keys or the generation counters needs a test that tries to get
  around it: a copied Key, a wrong PIN, an edited header.
- Never log or return a PIN, a recovery code or key material.
- Match the surrounding style.
- By submitting a contribution you agree to the [CLA](CLA.md).

## License

GPL-3.0-only.
