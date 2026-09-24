# Quickstart

## Abstract

This page is the install, build, and first-use path for `@keetanetwork/asn1-napi-rs`. It records the Makefile targets from the repository Makefile. It also states the GitHub Packages gate.

## Purpose

Read this page when you clone the repository or when you install the published package. After reading you can authenticate to GitHub Packages, install dependencies, build the NAPI addon, lint, test, and run one encode and decode round-trip.

## Install

`package.json` `name` is `@keetanetwork/asn1-napi-rs`. `package.json` `publishConfig.registry` is `https://npm.pkg.github.com`. Root `.npmrc` sets `@keetanetwork:registry=https://npm.pkg.github.com`.

```bash
npm install @keetanetwork/asn1-napi-rs
```

Add a GitHub personal access token to your `~/.npmrc` file.

```
//npm.pkg.github.com/:_authToken=YOUR_TOKEN
```

`package.json` `engines.node` is `>= 10`.

## Setup and build

The Makefile owns the recipes.

| Target | What you get |
| --- | --- |
| `make node_modules` | `npm clean-install` from `package.json` and `package-lock.json` |
| `make` | `index.js`, `index.d.ts`, and `asn1-napi-rs.node` |
| `make test` | `cargo test`, then Ava |
| `make do-lint` | eslint and rustfmt check |

`index.d.ts` may be absent until `make`. The Makefile `index.js` rule generates `index.js` and `index.d.ts`. That rule then appends the `ASN1AnyJS` union to `index.d.ts`.

```bash
make node_modules
make
```

## Test

```bash
make test
```

Ava specs live under `tests/`.

```bash
make do-lint
```

## One round-trip

The integer round-trip in `tests/integer.spec.ts` encodes a JS number through `JStoASN1`, emits BER through `toBER`, and decodes through `ASN1toJS`.

```ts
import * as lib from '..'

const value = 42
lib.ASN1toJS(lib.JStoASN1(value).toBER())
```

That call returns `BigInt(value)` in `tests/integer.spec.ts`. The same file also constructs `ASN1Decoder` from BER bytes and calls `intoInteger`. `tests/object.oid.spec.ts` uses the same `JStoASN1` / `toBER` / `ASN1toJS` path with an `ASN1OID` value.

## Major Assumptions and Assertions

- This page shows one integer round-trip rather than full type coverage.
- GitHub Packages authentication stays on the operator machine.
- `index.d.ts` may be absent until a local build finishes.
