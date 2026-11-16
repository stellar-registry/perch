<!--
Stacked-PR member. If a stack tool (gh-stack, Graphite, ghstack, Sapling) writes the
position and sibling list, delete the table below and keep only the three bold lines:
no tool can know those. Title: `type(scope): imperative summary`, at most 72 characters.
Delete these comments.
-->

## Stack

Part **k of n** of <epic or issue link>. Base: `<branch>` (<PR URL>). Next: <PR URL>.

| # | PR | Scope | State |
|---|----|-------|-------|
| 1 | <url> | <one line> | merged / in review / draft |
| ▶ k | this PR | <one line> | |

**Reviewed here:** <the concern this member owns>.
**Reviewed elsewhere:** <what this diff shows that belongs to another member, or is only
carried or moved here, with a link>.
**Depends on:** <what from earlier members this relies on>.
**Compare with the last revision:** `git range-diff <old-base>..<old-head> <base>..<head>`

## Why

<!-- The problem this member solves and why this approach. -->

## What changes

<!-- Behaviour delta of THIS member, then what does NOT change. -->

## How to review

<!-- Start at: `path::symbol`. Risky: 1-3 places. Skim: carried or generated content. -->

## Evidence

<!-- Builds and passes tests at THIS member's head, not only at the top of the stack:
the commands and counts. -->

## Decisions for review

<!-- Choices a reviewer could make differently, and the question you want answered. -->

## After merge

<!-- Merge order: after <PR URL>; retarget the next member's base once this lands. -->
