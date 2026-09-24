# Documentation Standard

## Abstract

This page is the documentation contract for the `@keetanetwork/asn1-napi-rs` package. It states what belongs in a documentation page. It also fixes the prose, the register, and the page shape.

## Purpose

An engineer reads this page before writing or reviewing documentation in this repository. After reading, the engineer can tell whether a page belongs in the tree. The engineer can also write the page in the expected prose and shape.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) [RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174) when, and only when, they appear in all capitals, as shown here.

This page is the one home for that declaration. Other pages in this tree MAY use those keywords under this home. They MUST NOT repeat this section.

## The inclusion test

Documentation earns its maintenance cost by holding the knowledge that lives outside any one file. A page MUST carry at least one of the following.

- An invariant that spans several files, which puts it beyond the reach of a single file.
- A decision and the alternative it rejected, so a later reader keeps it closed.
- A contract that binds consumer behavior, such as an encode or decode entry.
- A procedure an operator runs under pressure.

The source is the home for export lists, type fields, and the existence of each module file. A page that needs a symbol cites that symbol as `Symbol` in `path/to/file`. The [Overview](README.md) names the living pages.

One body of knowledge takes one page as its home. A second page that needs it MUST link to that home rather than restate it.

Contract pages live as UPPER_CASE names under `docs/`. Supplementary guides live as lowercase names under `docs/resources/`. This package has no `src/*/docs/` modules.

[Architecture](ARCHITECTURE.md) holds the package collaboration graph and the interaction path. That page MUST include at least one Mermaid diagram with keyword-safe ids. It MUST name the owning module and one key symbol on each step of that path. It MUST state contracts in the positive. [Quickstart](QUICKSTART.md) is the home for fenced usage examples. The source is the home for the public export list.

When a page must name a symbol, it cites that symbol as `Symbol` in `path/to/file`. The source carries its own detail.

## Prose

A page uses full sentences and keeps their articles. A sentence holds one topic. A sentence does not join independent clauses with a semicolon. Prose uses the active voice and the present tense.

A page uses the exact technical noun, in code font, on every mention of the same thing. A page uses the ASCII hyphen only and writes each relation as words. A page prefers a table, a list, or a diagram when that form reorganizes substance.

A page states contracts in the positive. A page names the command or path that Makefile, `package.json`, `.npmrc`, or the cited source file states.

Each register addresses its reader differently. A page MUST hold one register throughout.

| Register | Reader | Voice |
| --- | --- | --- |
| Concept | An engineer building a model of the system | Third person, declarative |
| Implementation | An engineer integrating the software into a service | Second person, imperative |
| Operations | An operator under time pressure | Second person, imperative, one action per step |
| Reference | An engineer checking an exact contract | Third person, terse, declarative |

## Page shape

Every shaped page under `docs/` MUST carry the following sections, in the following order.

1. **Title.** The subject of the page, as a noun phrase.
2. **Abstract.** Two or three sentences on what the page holds.
3. **Purpose.** Who reads the page, and what they can do afterward.
4. **Body.** The sections that carry the content, which SHOULD sit in the correct dependency order.

A page SHOULD cite the test that encodes an invariant when that file is the enforcement point. One citation replaces a prose argument that the guarantee holds.

The root `README.md` MAY stay a thin pointer. That page does not use this page shape. It MUST NOT redeclare Requirements Language.

Navigation and audience live on the [Overview](README.md). This page MUST NOT carry a page index.

A Mermaid diagram, when used, MUST give every node and participant an id that is not a Mermaid keyword. Ids such as `fn_js_to_asn1` and `enc_asn1` stay keyword-safe. A node id MUST stay outside the reserved words `graph`, `end`, and `subgraph`.
