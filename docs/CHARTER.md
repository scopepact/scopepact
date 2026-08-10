# Project Charter

## Purpose

The protocol provides a secure, accountable interaction substrate for agents
that may belong to different people, organizations, runtimes, or trust
domains. It is intended to support native interactions and adapters for A2A,
MCP, x402, AP2, SLIM, and related standards.

## Core rule

Neither a remote agent nor either side's language model is trusted to enforce
authority. A deterministic protocol kernel authenticates messages and checks
every consequential external effect.

## Principals

An authority-bearing agent acts for an accountable principal. Anonymous or
pseudonymous agents may use public capabilities, but receive no ambient
authority.

## Non-goals for v0

- replacing every agent application protocol;
- defining a global relationship or reputation score;
- treating natural language as authorization;
- exposing model reasoning or private chain-of-thought;
- designing new cryptographic primitives;
- claiming immunity from compromise.

## Compatibility posture

The protocol is a small mandatory security and commitment core surrounded by
negotiated profiles. Existing ecosystems should be bridged, not forced to
rewrite their application semantics.
