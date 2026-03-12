# docs/ Directory

This directory contains design documents for the Talos project. Each document follows a versioned naming convention and a standardized structure.

## Naming Convention

```
v<version>-<slug>.md
```

Examples:
- `v0.1.0-design.md` — Initial design document for the mTLS TCP proxy
- `v0.2.0-cache-invalidation.md` — Design for LISTEN/NOTIFY cache invalidation

## Document Template

New design documents should follow the structure below. Not all sections are required for every document — include what is relevant and omit sections that do not apply.

```markdown
# <Title>

> **<Name>** (<origin>): Brief mythological or conceptual epigraph connecting
> the name to the system's purpose.

| Field        | Value      |
| ------------ | ---------- |
| Document ID  | NNN        |
| Status       | Draft      |
| Author       | —          |
| Created      | YYYY-MM-DD |
| Last Updated | YYYY-MM-DD |

---

## Table of Contents

1. [Business Reason](#1-business-reason)
2. [Business Impact](#2-business-impact)
3. [Actors](#3-actors)
4. [Use Cases](#4-use-cases)
5. [Acceptance Criteria](#5-acceptance-criteria)
6. [Architecture](#6-architecture)
7. [Component Design](#7-component-design)
8. [Data Model](#8-data-model)
9. [CLI Interface Design](#9-cli-interface-design)
10. [Application Configuration](#10-application-configuration)
11. [Security Considerations & Critique](#11-security-considerations--critique)
12. [Technical Feasibility Assessment](#12-technical-feasibility-assessment)
13. [Existing OSS Landscape](#13-existing-oss-landscape)
14. [Assumptions](#14-assumptions)
15. [Risks & Mitigations](#15-risks--mitigations)
16. [Future Considerations](#16-future-considerations)

---

## 1. Business Reason

Why this system/feature exists. What problem does it solve? What gap in
existing solutions does it address?

---

## 2. Business Impact

| Dimension      | Impact |
| -------------- | ------ |
| **Security**   |        |
| **Compliance** |        |
| **Operations** |        |
| **Availability** |      |
| **Developer Experience** | |

---

## 3. Actors

| Actor | Description |
| ----- | ----------- |
|       |             |

---

## 4. Use Cases

### UC-N: <Title>

> **As a** <actor>,
> **I want to** <action>,
> **So that** <outcome>.

---

## 5. Acceptance Criteria

### AC-N: <Title>

\```
AS      a <actor>
GIVEN   <precondition>
WHEN    <action>
THEN    <expected outcome>
\```

---

## 6. Architecture

Include Mermaid diagrams where helpful:
- High-level architecture (component topology)
- Multi-service / multi-instance topology (if applicable)
- Connection / request flow (sequence diagrams)

---

## 7. Component Design

Break down the system into its major components. For each component, describe:
- Responsibilities (table format)
- Lifecycle / flow (numbered steps)

---

## 8. Data Model

- Entity relationship diagram (Mermaid erDiagram)
- SQL schema (DDL)
- Hot-path queries and their index strategy

---

## 9. CLI Interface Design

Show example CLI invocations with expected output for each subcommand.

---

## 10. Application Configuration

- Full annotated YAML configuration
- Environment variable overrides
- Minimal development configuration

---

## 11. Security Considerations & Critique

### 11.1 Validated: Strong Design Choices

| Decision | Assessment |
| -------- | ---------- |
|          |            |

### 11.2 Critique & Required Changes

Detail any critical, important, or notable security concerns with rationale
and design decisions.

---

## 12. Technical Feasibility Assessment

For each key technical choice, provide:

| Aspect | Detail |
| ------ | ------ |
|        |        |

Include verdict (Fully feasible / Feasible with caveats / Risky).

---

## 13. Existing OSS Landscape

| Project | Category | Relevant Capabilities | Gaps |
| ------- | -------- | --------------------- | ---- |
|         |          |                       |      |

Explain the value proposition vs. existing solutions.

---

## 14. Assumptions

| # | Assumption | Rationale |
| - | ---------- | --------- |
|   |            |           |

---

## 15. Risks & Mitigations

| # | Risk | Severity | Mitigation |
| - | ---- | -------- | ---------- |
|   |      |          |            |

---

## 16. Future Considerations

| Priority | Feature | Description |
| -------- | ------- | ----------- |
|          |         |             |

---

## Appendix (optional)

Additional reference material: platform-specific instructions, dependency
lists, deployment guides, etc.
```
