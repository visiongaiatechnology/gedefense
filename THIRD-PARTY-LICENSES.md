# Third-Party Components and Data Licenses

GeDefense contains third-party software components and public data sets. Their
licenses are separate from the AGPL-3.0-only license of GeDefense itself.

## jsVectorMap 1.7.0 — MIT License

- Project: [themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap)
- Vendored files: `control/web/vendor/jsvectormap/` including the SVG world map
  (`js/world-merc.js`) used by the dashboard overview map.
- Upstream map asset: [world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js)
- License: [MIT](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE)

Copyright (c) 2020 Mustafa Omar

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## IP-to-Country and IP-to-ASN data — iplocate/ip-address-databases

- Project: [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases)
- Data used for the offline GeoIP/ASN table `geoip.csv`.
- License: **Creative Commons Attribution-ShareAlike 4.0 International**
  (CC BY-SA 4.0), <https://creativecommons.org/licenses/by-sa/4.0/>.

The data has been transformed for GeDefense: ranges were converted to CIDRs,
merged/coalesced, enriched with origin-ASN metadata, and written in the
`network,country_code,country_name,latitude,longitude,asn,as_name` format.
The transformed database is distributed under the same CC BY-SA 4.0 terms.
Attribution: *IP-to-Country and IP-to-ASN databases by iplocate
(https://github.com/iplocate/ip-address-databases), licensed CC BY-SA 4.0;
changes were made by VisionGaia Technology for GeDefense.*

## Additional GeoIP / Origin-ASN sources used by the updater

- **DB-IP Lite** — <https://db-ip.com/> — Creative Commons Attribution 4.0
  International (CC BY 4.0). Attribution required.
- **sapics/ip-location-db** — <https://github.com/sapics/ip-location-db> —
  Public Domain Dedication and License (PDDL) for origin-ASN data.

These are public data sets; the GeDefense project does not claim endorsement by
their maintainers. See `README.md` for operational notes on updating the local
database.

## Vendored JavaScript libraries

The dashboard vendors its runtime assets locally and loads no CDN at runtime.
The jsVectorMap license above applies to the vendored map code. Other vendored
assets retain the license notices shipped next to them under
`control/web/vendor/`.

## Qt 6 (desktop tray)

The desktop/tray client links dynamically against Qt 6 (LGPL-3.0 or the
commercial Qt terms chosen by the distributor). Qt is not vendored; the
distribution packages are used. See <https://www.qt.io/licensing/>.
