# The acme-not-a-joke website

A [Kitchen-Sink](https://kitchensink-tech.github.io/) site, the same shape as
[agents-exe's](https://github.com/lucasdicioccio/agents-exe/tree/main/website).
A page is a `.cmark` file split into *sections* (content, metadata, CSS);
Kitchen-Sink assembles them into a static site.

- `src/` — the source: `kitchen-sink.json` (site config), the hand-written
  pages (`index.cmark`, `introducing-acme-not-a-joke.cmark`, `llms.txt`), the
  layout pages (`topics`, `hashtags`, `glossary`) and the CSS/JS they
  reference.
- `src/logo.svg` — the logo, hand-written; `src/logo.png` and
  `src/favicon.png` are rendered from it and are what the pages reference
  (`convert -background none -density 192 logo.svg -resize 512x512 logo.png`,
  and `-resize 64x64 favicon.png`).
- `scripts/publish.sh` — produces the site into the repository's `docs/`.
- `www/` — the dev server's output directory (gitignored).

The published site is the repository's `docs/` directory, which GitHub Pages
serves from `main`. `docs/` is produce output: edit `website/src/` and
publish again rather than editing it by hand.

## Preview

```sh
kitchen-sink serve --srcDir website/src --outDir website/www --servMode DEV --httpPort 7655
```

Then open http://localhost:7655/acme-not-a-joke/index.html (pages are served
under the `basePath`). The dev server rebuilds on file changes
under `src/`.

## Publish

Produce the site into `docs/` and commit it:

```sh
./website/scripts/publish.sh    # kitchen-sink produce --srcDir website/src --outDir docs
```

`kitchen-sink.json`'s `basePath` is `/acme-not-a-joke`, so every absolute
`/x.html` link and every CSS import (through `$ctx.pathPrefix`) resolves under
`https://lucasdicioccio.github.io/acme-not-a-joke/`.

## Write a new article

Add a `.cmark` file in `src/` with the `article` layout; the quickest way is
to copy `introducing-acme-not-a-joke.cmark` and change its preamble, topic,
summary and content sections. The index page lists the latest articles on
its own.

## Learn more

- [Features](https://kitchensink-tech.github.io/features.html) — what
  Kitchen-Sink can do.
- [Sections](https://kitchensink-tech.github.io/sections.html) — the
  section format used inside each `.cmark` file.
