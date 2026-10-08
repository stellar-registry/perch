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

## Interactive learning tools

`theme/lab-model.js` contains a deliberately small teaching model for the CI rule and three-valued operators. `theme/labs.js` progressively adds controls to the marked chapter blocks; `theme/labs.css` inherits mdBook's themes and includes mobile and print styles. No CDN, analytics, wallet connection, network calls, or stored progress are needed.

The CI sandbox reads the same included fixture as the chapter. It shows one rule, assumes the signer result, and illustrates scope/expiry separately from the interpreter trace. It is not a production compiler or a verified interpreter. The static text remains available if JavaScript is disabled or a widget fails to initialize.

Run `node --test book/tests/*.test.cjs` from the repository root. These tests check decision boundaries, malformed ledger input, the complete verdict truth tables, and supported leaves against the frozen conformance cases. After building, check the sandbox presets, keyboard controls, evaluator steps, quiz feedback, narrow layout, and print view in a browser. CI runs the model checks with the book's runnable example in the `perch-js` package leg only.
