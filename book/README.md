# Building The Perch Book

The book uses [mdBook](https://rust-lang.github.io/mdBook/), with a progressive tutorial, searchable sidebar, themes, and print output. Sources live in `src/`; `SUMMARY.md` controls chapter order. Generated HTML is not committed.

From the repository root:

```sh
cargo install mdbook --locked --version 0.4.52
just book           # build to target/perch-book
just book-serve     # serve at http://localhost:3000
```

Use mdBook 0.4.52, also pinned in the shared CI action. No Rust doctests run: the book teaches a JSON policy language, and its Lean snippet is an excerpt, not a standalone program.

The running JSON example is included from the existing testdata fixture. The TypeScript example is included from `examples/ci-publish.mjs`; run it after `npm ci` in `packages/perch-js`. CI runs it alongside the TypeScript checks. Validate edits with `just book` and inspect the rendered pages, especially links and code examples.

Pages and same-repository PR previews build the book into `docs/book/` before publishing `docs/`. The landing page links to the book and the existing slide deck. Relative links keep PR previews self-contained. A separate read-only CI job builds the book for all PRs, including forks.

When changing language or proof claims, inspect the actual IR, compiler, and Lean declarations. Distinguish schema support, compiler support, tested behavior, and proved model behavior. Keep terminology accessible and state assumptions beside claims.
