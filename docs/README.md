# Overview

## Abstract

This guide is the table of contents for the `@keetanetwork/asn1-napi-rs` documentation. Contract pages live on [Architecture](ARCHITECTURE.md), [Quickstart](QUICKSTART.md), and [Documentation Standard](STANDARD.md).

## Purpose

An engineer reads this guide to find the page that holds each inbound question. After reading, the engineer can open the contract page that owns that question.

## Living pages

| Next question | The page |
| --- | --- |
| How do encode and decode modules collaborate? | [Architecture](ARCHITECTURE.md) |
| How does a reader install, build, and run one round-trip? | [Quickstart](QUICKSTART.md) |
| How does a writer review a page in this tree? | [Documentation Standard](STANDARD.md) |

| Path | Role |
| --- | --- |
| Root `README.md` | Thin pointer into this tree |
| `docs/README.md` | This overview |
| `docs/STANDARD.md` | Documentation contract |
| `docs/ARCHITECTURE.md` | Collaboration graph and interaction path |
| `docs/QUICKSTART.md` | Install, build, and first use |

This package has no `src/*/docs/` modules. This tree has no `docs/resources/` pages.

## Major Assumptions and Assertions

- The living table of contents names [Architecture](ARCHITECTURE.md), [Quickstart](QUICKSTART.md), and [Documentation Standard](STANDARD.md).
- Package identity is `@keetanetwork/asn1-napi-rs` in `package.json` `name`.
- Root `README.md` is a thin pointer into this tree.
- `docs/README.md` holds the overview table of contents.
- `docs/STANDARD.md` holds the documentation contract.
- `docs/ARCHITECTURE.md` holds the collaboration graph and interaction path.
- `docs/QUICKSTART.md` holds install, build, and first use.
- This package has no `src/*/docs/` modules.
- This tree has no `docs/resources/` pages.
