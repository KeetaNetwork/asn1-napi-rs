# `@keetapay/asn1-napi-rs`

[ci_status]: https://github.com/KeetaPay/asn1-napi-rs/actions/workflows/CI.yml/badge.svg
[ci]: https://github.com/KeetaPay/asn1-napi-rs/actions/workflows/CI.yml
[lint_status]: https://github.com/KeetaPay/asn1-napi-rs/actions/workflows/lint.yml/badge.svg
[lint]: https://github.com/KeetaPay/asn1-napi-rs/actions/workflows/lint.yml

[![ci_status]][ci] [![lint_status]][lint]

# About

This project utilizes [napi-rs](https://github.com/napi-rs/napi-rs) to build native Rust functionality that can be consumed in NodeJS. This library specifically addresses ASN.1 encoding and decoding for the [@keetapay/node](https://github.com/KeetaPay/node) project. It contains all critical functionality for encoding/decoding ASN.1 BER for all KeetaNet node functionality.

## Install this package

```bash
yarn add @keetapay/asn1-napi-rs
```

Note: You will need a [GitHub personal access token](https://github.com/settings/tokens) added to your `~/.npmrc` file like so:

```
//npm.pkg.github.com/:_authToken=YOUR_TOKEN
```

## Supported Environments

|                  | node14 | node16 | node18 |
| ---------------- | ------ | ------ | ------ |
| Windows x64      | ✓      | ✓      | ✓      |
| Windows x32      | ✓      | ✓      | ✓      |
| Windows arm64    | ✓      | ✓      | ✓      |
| macOS x64        | ✓      | ✓      | ✓      |
| macOS arm64      | ✓      | ✓      | ✓      |
| Linux x64 gnu    | ✓      | ✓      | ✓      |
| Linux x64 musl   | ✓      | ✓      | ✓      |
| Linux arm gnu    | ✓      | ✓      | ✓      |
| Linux arm64 gnu  | ✓      | ✓      | ✓      |
| Linux arm64 musl | ✓      | ✓      | ✓      |
| Android arm64    | ✓      | ✓      | ✓      |
| Android armv7    | ✓      | ✓      | ✓      |
| FreeBSD x64      | ✓      | ✓      | ✓      |

## Local Development

Library development was done using rustc v1.64.0, yarn v3.2.3, nodejs v14.19.0 in Visual Studio Code.

## Requirements

- Install the latest [Rust](https://www.rust-lang.org/tools/install) (Minimum supported v1.60.0)
- Install [Node.js@14+](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) which fully supported `Node-API`
- Install [Yarn](https://classic.yarnpkg.com/lang/en/docs/install)

### Setup

Once prerequisites are installed, you can setup the initial project easily using:

```bash
yarn setup
```

### Building

You can build the entire project or just the rust using the following:

```bash
# Project
yarn build

# Rust
cargo build
```

When running the `yarn build` command, you can see `asn1-napi-rs.[darwin|win32|linux].node` file in project root. This is the native addon built from the rust code. These files should not be committed and are already in the `.gitignore` file.

### Testing

All JavaScript/TypeScript tests are located in the `tests` directory within the project root. All Rust tests are located in a `test` module in the file containing the code to be tested. With [ava](https://github.com/avajs/ava), run `yarn test` to testing native addon.

```bash
yarn build && yarn test
```

And you will see:

```bash
$ yarn test

  ✔ integer › JS number to ASN1 conversion
  ✔ integer › ASN1 to Js number conversion from byte code
  ✔ integer › ASN1 to Js number conversion from base64
  ✔ integer › ASN1 to Js number conversion round trip
  ...

  [number] tests passed
```

With [cargo](https://doc.rust-lang.org/cargo/commands/cargo-test.html), run `cargo test` to run the Rust tests.

```bash
cargo test
```

And you will see:

```bash
running [number] tests
test asn1::test::test_asn1_into_bytes ... ok
test asn1::test::test_asn1_into_date ... ok
...
```

### Benchmarking

There are a few benchmarks of critical functionality available which tests the Rust implementations of functions against their TypeScript counterparts. You can run these tests using:

```bash
yarn bench
```

And you will see:

```bash
Running "Encode/Decode Block from Buffer" suite...
Progress: 100%

  Rust ASN1toJS - JStoASN1 Test Block:
    25 048 ops/s, ±3.18%   | fastest

  JavaScript ASN1toJS - JStoASN1 Test Block:
    1 817 ops/s, ±4.89%    | slowest, 92.75% slower

Finished 2 cases!
  Fastest: Rust ASN1toJS - JStoASN1 Test Block
  Slowest: JavaScript ASN1toJS - JStoASN1 Test Block
...
```

## Functionality

Key function exports:

- JStoASN1
- ASN1toJS
- BigIntToBuffer

## CI/CD

With GitHub Actions, each commit and pull request will be built and tested automatically in [`node@14`, `node@16`, `@node18`] x [`macOS`, `Linux`, `Windows`] matrix.

### Release

Releases are managed through GitHub actions. Once ready, tag a release like so using the [semantic versioning](https://semver.org) style prefixed with a "v":

```bash
# Creates an annotated tag
git tag -s -a "v1.x.x" -m ":bookmark: v1.x.x"
# Pushes tags to remote
git push --tags
```

Then, create a release in GitHub which will trigger the GitHub action and deploy new GitHub NPM package for the release. The rest will be done for you and you can then require the new version as usual in the project this library is used in.
