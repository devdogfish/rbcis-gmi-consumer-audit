# RBCIS public GMI consumer audit

## What this report is about

GMI is a shared service used by RBC Investor Services pages to retrieve information such as market updates, calendars, tax material, and other custody content. Some public pages communicate with GMI directly from a visitor's browser. Browser-side calls and their supporting JavaScript are visible to the public, so calls that include embedded authentication deserve review even when the underlying content is intended to be public. This audit identifies where those calls appear; it does not by itself claim that every occurrence is exploitable.

## Main findings

- 593 candidate URLs checked across `www.rbcis.com` and `apps.rbcits.com`.
- 284 reachable public HTML pages reviewed: 253 on `www.rbcis.com` and 31 on `apps.rbcits.com`.
- 115 of 115 supplied GMI JavaScript files inspected.
- 77 scripts contain GMI calls; 64 contain client-embedded authentication.
- 24 confirmed page-to-script imports involving 15 distinct supplied scripts.
- 168 GMI consumer records: 23 mapped to public pages and 145 source-only records with no importing public page found.
- 68 GMI-calling scripts remain unmapped to the reachable public pages reviewed.

## How to read the results

**Public** means a call was connected to a reachable public page. **Unmapped** means the JavaScript contains a GMI call, but no importing page was found in the public page set; it does not mean the script is unused. **Client-embedded authentication** means authentication material was present in publicly delivered JavaScript. Credential values were deliberately excluded from every published file.

## 1. DRIP page finding

| Page | JavaScript source | GMI endpoint | Request | Access | Authentication | Summary |
|---|---|---|---|---|---|---|
| [apps.rbcits.com/gmi/drip](https://apps.rbcits.com/gmi/drip/) | Inline page script | `/GMIService/api/DripReport` | Client-side `GET` using `jQuery.ajax` | Public | Client-embedded Basic authentication | The public DRIP page directly requests a GMI report from the visitor's browser. |

## 2. Confirmed public page-to-script imports

| # | Public page | JavaScript file | GMI endpoint(s) | Authentication | Finding / notes |
|---:|---|---|---|---|---|
| 1 | [English market newsflash](https://www.rbcis.com/en/gmi/global-custody/market-newsflash.page) | `market-newsflash-25.js` | `/GMIService/api/Search?gmiFormId=1&count=20`<br>`/GMIService/api/Search?gmiFormId=1` | Client-embedded Basic | Two client-side GMI GET calls confirmed. |
| 2 | [English market newsflash](https://www.rbcis.com/en/gmi/global-custody/market-newsflash.page) | `media-inquiries-responsive.js` | None detected | Not applicable | Responsive-page utility; no GMI call found in this file. |
| 3 | [English global custody](https://www.rbcis.com/en/gmi/global-custody.page) | `mainpage.js` | `/GMIService/api/Search?gmiFormId=1&count=4`<br>`/GMIService/api/Search?gmiFormId=3&count=4` | No explicit authentication observed | Two client-side GMI GET calls confirmed; cookies may still apply. |
| 4 | [English terms and conditions](https://www.rbcis.com/en/gmi/global-custody/terms-and-conditions.page) | `secnav.js` | None detected | Not applicable | Navigation utility; no GMI call found in this file. |
| 5 | [English tax profiles](https://www.rbcis.com/en/gmi/global-custody/tax-profiles.page) | `tax-bulletins-23.js` | `/GMIService/api/Search?gmiFormId=2&count=20`<br>`/GMIService/api/Search?gmiFormId=2` | Client-embedded Basic | Two client-side GMI GET calls confirmed. |
| 6 | [English market profiles](https://www.rbcis.com/en/gmi/global-custody/market-profiles.page) | `market-profiles.js` | None detected | Not applicable | Imported by the page; no GMI call found in this file. |
| 7 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | `jspdf.min.js` | None detected | Not applicable | PDF-generation library; no GMI call found. |
| 8 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | `jspdf.plugin.autotable.min.js` | None detected | Not applicable | PDF-table plugin; no GMI call found. |
| 9 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | `holiday-calendar-26-1-bundle.js` | `/GMIService/api/Search?gmiFormId=5&date=self.selectedDay()`<br>`/GMIService/api/Search?gmiFormId=5` | No explicit authentication observed | Two client-side GMI GET calls confirmed; cookies may still apply. |
| 10 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | `hide-holidays.js` | None detected | Not applicable | Calendar display helper; no GMI call found. |
| 11 | [English updates](https://www.rbcis.com/en/gmi/global-custody/updates.page) | `updates-25.js` | `/GMIService/api/Search?gmiFormId=3&count=10`<br>`/GMIService/api/Search?gmiFormId=3` | Client-embedded Basic | Two client-side GMI GET calls confirmed. |
| 12 | [English GMI tax bulletins login page](https://www.rbcis.com/en/login/gmi-tax-bulletins.page) | `secnav.js` | None detected | Not applicable | Navigation utility; no GMI call found in this file. |
| 13 | [French global custody](https://www.rbcis.com/fr/gmi/global-custody.page) | `mainpage.js` | `/GMIService/api/Search?gmiFormId=1&count=4`<br>`/GMIService/api/Search?gmiFormId=3&count=4` | No explicit authentication observed | Two client-side GMI GET calls confirmed; cookies may still apply. |
| 14 | [English GMI terms login page](https://www.rbcis.com/en/login/gmi-terms-and-conditions.page) | `secnav.js` | None detected | Not applicable | Navigation utility; no GMI call found in this file. |
| 15 | [French market newsflash](https://www.rbcis.com/fr/gmi/global-custody/market-newsflash.page) | `market-newsflash-25-fr.js` | `/GMIService/api/Search?gmiFormId=1&count=20`<br>`/GMIService/api/Search?gmiFormId=1` | Client-embedded Basic | Two client-side GMI GET calls confirmed. |
| 16 | [French terms and conditions](https://www.rbcis.com/fr/gmi/global-custody/terms-and-conditions.page) | `secnav.js` | None detected | Not applicable | Navigation utility; no GMI call found in this file. |
| 17 | [French tax profiles](https://www.rbcis.com/fr/gmi/global-custody/tax-profiles.page) | `tax-bulletins.js` | `/GMIService/api/Search?gmiFormId=2&count=20`<br>`/GMIService/api/Search?gmiFormId=2` | Client-embedded Basic | Two client-side GMI GET calls confirmed. |
| 18 | [French market profiles](https://www.rbcis.com/fr/gmi/global-custody/market-profiles.page) | `market-profiles.js` | None detected | Not applicable | Imported by the page; no GMI call found in this file. |
| 19 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | `jspdf.min.js` | None detected | Not applicable | PDF-generation library; no GMI call found. |
| 20 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | `jspdf.plugin.autotable.min.js` | None detected | Not applicable | PDF-table plugin; no GMI call found. |
| 21 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | `holiday-calendar-24.1-bundle.js` | `/GMIService/api/Search?gmiFormId=5&date=self.selectedDay()`<br>`/GMIService/api/Search?gmiFormId=5` | No explicit authentication observed | Two client-side GMI GET calls confirmed; cookies may still apply. |
| 22 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | `hide-holidays.js` | None detected | Not applicable | Calendar display helper; no GMI call found. |
| 23 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | `holiday-calendar.js` | `/GMIService/api/Search?gmiFormId=5&date=self.selectedDay()`<br>`/GMIService/api/Search?gmiFormId=5` | No explicit authentication observed | Two client-side GMI GET calls confirmed; one uses jQuery shorthand. |
| 24 | [French updates](https://www.rbcis.com/fr/gmi/global-custody/updates.page) | `updates-25.js` | `/GMIService/api/Search?gmiFormId=3&count=10`<br>`/GMIService/api/Search?gmiFormId=3` | Client-embedded Basic | Two client-side GMI GET calls confirmed. |

## How to use the attached workbook

Start with the two domain sheets for the detailed consumer records, then use the supporting sheets when more context is needed:

- **apps.rbcits.com**: the DRIP page finding.
- **www.rbcis.com**: detailed GMI consumer records, including public-page and unmapped source findings.
- **Page Imports**: the 24 confirmed public page-to-JavaScript relationships summarized above.
- **Script Inventory**: all 115 reviewed scripts, including call counts, authentication classification, and whether a public importing page was found.
- **Coverage**: crawl scope, totals, excluded URLs, method, and limitations.

Each detailed consumer row identifies the page, JavaScript source, line, endpoint, request method, execution side, page access, authentication classification, call mechanism, confidence, and a plain-language summary.

## How this was produced

A recursive public-only crawl followed same-host links from the site roots, previously confirmed pages, and public discovery hints while skipping individual errors; every reachable page was then checked for direct script imports, loaded scripts were inspected for GMI request patterns and static or literal child-script references, and the results were reconciled against the supplied 115-file inventory. No authenticated pages were accessed, no requests were executed against discovered GMI endpoints, and no credential values were retained.

## Limits

The crawl reached an empty queue for its public discovery set, but no crawler can discover an entirely unlinked URL that is absent from all known sources; proving those orphan routes requires a CMS or origin route inventory. Computed runtime loaders, authenticated pages, and server-side consumers were outside this review.
