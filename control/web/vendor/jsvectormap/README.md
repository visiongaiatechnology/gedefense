# Vendored: jsVectorMap 1.7.0

MIT License — Copyright (c) 2020 Mustafa Omar. The upstream licence text is in
`LICENSE` and applies to everything in this directory, including `maps/`.

## Why it is vendored

The dashboard is served from the embedded filesystem of the control plane and is a
native ES-module graph with no bundler and no package manager at runtime. Every
asset is served from `/assets/{name}` against an explicit allowlist. A runtime CDN
is forbidden by the product's own standard and by `script-src 'self'`, and the
whole point of a local GeoIP/ASN path is that no request leaves the host. The map
therefore has to be a local file.

## What was copied

| From | To |
|---|---|
| `packages/jsvectormap/src/js/**` (43 files) | `js/**` |
| `packages/jsvectormap/src/scss/**` (2 files) | `scss/**` |
| `packages/maps/src/world-merc.js` | `maps/world-merc.js` |
| `packages/jsvectormap/LICENSE` | `LICENSE` |
| repository `LICENSE` | `maps/LICENSE` |
| `packages/jsvectormap/package.json` | `package.json.upstream` (provenance only, never served) |

`world-merc` is used rather than `world` because the live view plots threat sources
by latitude and longitude. Mercator is the projection an operator expects for that,
and both files carry a `projection` block, so `coordsToPoint` resolves `[lat, lng]`
rather than raw SVG coordinates.

## Deviations from upstream — complete list

Three edits, each one token, each required by this project's constraints. Nothing
else differs.

### 1. `js/index.js` — the SCSS import is removed

```diff
-import '../scss/jsvectormap.scss'
```

A browser cannot import SCSS. Upstream expects a bundler with a Sass loader; this
project has neither. The stylesheet is shipped as a plain CSS file compiled from
the vendored SCSS, and the compilation is documented in its own header.

### 2. `js/index.js` — the global assignment is removed

```diff
-export default window.jsVectorMap = jsVectorMap
+export default jsVectorMap
```

Upstream installs a `window.jsVectorMap` global as a side effect of the import. A
security product should not add a writable global that any other script on the page
could replace, and nothing in this integration needs it: the map registry is
reached through the imported class.

### 3. `maps/world-merc.js` — the data literal is exported instead of registered

```diff
-jsVectorMap.addMap("world_merc", { ... });
+const worldMercatorMap = { ... };
+export default worldMercatorMap;
```

The upstream file is a classic script that calls a global. As a module it would
throw on import. The object literal between the braces is **byte-identical** to
upstream — the transformation only replaces the wrapper, and the build verified
that the 176 country paths are unchanged before and after. Registration happens in
`control/web/geo-map.js` through `jsVectorMap.addMap`, which is also what keeps the
data module free of side effects and free of any load-order dependency.

## Trusted Types

The dashboard serves `require-trusted-types-for 'script'`. The library has exactly
**two** `innerHTML` assignments in the whole tree, and both are opt-in behind an
`html` argument:

| File | Site | Reached when |
|---|---|---|
| `js/util/index.js` | `createElement(type, classes, content, html = false)` | `html === true` |
| `js/components/tooltip.js` | `text(string, html = false)` | `html === true` |

The only caller that passes `html = true` is `js/core/setupZoomButtons.js`, which
builds the `+` and `−` buttons from the hardcoded entities `&#43;` and `&#x2212;`.

Everything else — including the entire SVG construction — goes through
`createElementNS`, `setAttribute` and `textContent`. That is why this integration
works without weakening the Content Security Policy: `control/web/geo-map.js`
creates the map with `zoomButtons: false`, so the single `html = true` path is
never executed. A contract test asserts that, asserts that the vendored tree still
contains exactly one `html = true` call site, and asserts that our own modules
contain no Trusted Types sink at all. If a future vendored version adds a second
`html = true` call site, that test fails rather than the browser throwing at
runtime.

**Do not enable `zoomButtons` without re-reading this section.** The zoom controls
in this product are rendered by `control/web/geo-map.js` with `textContent`.

## Updating this vendored copy

1. Replace `js/`, `scss/`, `maps/world-merc.js`, `LICENSE` and
   `package.json.upstream` from the new upstream revision.
2. Re-apply the three deviations above.
3. Recompile `jsvectormap.css` from the new SCSS and update its source header.
4. Run `go test ./...` — the vendored-asset contract tests fail if the allowlist,
   the Trusted Types property or the stylesheet coverage no longer holds.
