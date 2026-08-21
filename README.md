# RBCIS public GMI consumer audit

## Overview

GMI is a shared service used by RBC Investor Services pages. This audit identifies public pages and JavaScript that call it, with emphasis on browser-visible embedded authentication. Findings are review points, not proof of exploitability. The review used public-only crawling and static source inspection; no authenticated pages or GMI endpoints were accessed, and no credential values were retained.

## Key results

- 284 reachable public pages reviewed.
- 115 JavaScript files reviewed.
- 77 scripts call GMI; 64 contain client-embedded authentication.
- 24 page-to-script imports and 168 consumer records; 68 GMI scripts had no public importing page identified.

## 1. DRIP page finding

| Page | JavaScript source | GMI endpoint | Request | Access | Authentication | Summary |
|---|---|---|---|---|---|---|
| [apps.rbcits.com/gmi/drip](https://apps.rbcits.com/gmi/drip/) | [Inline page script](https://apps.rbcits.com/gmi/drip/) | `/GMIService/api/DripReport` | Client-side `GET` using `jQuery.ajax` | Public | Client-embedded Basic authentication | Direct client-side GMI request from a public page. |

## 2. Confirmed public page-to-script imports

| # | Public page | JavaScript file | GMI endpoint(s) | Authentication | Finding / notes |
|---:|---|---|---|---|---|
| 1 | [English market newsflash](https://www.rbcis.com/en/gmi/global-custody/market-newsflash.page) | [market-newsflash-25.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/market-newsflash-25.js) | `/GMIService/api/Search?gmiFormId=1&count=20`<br>`/GMIService/api/Search?gmiFormId=1` | Client-embedded Basic | 2 GET calls confirmed. |
| 2 | [English market newsflash](https://www.rbcis.com/en/gmi/global-custody/market-newsflash.page) | [media-inquiries-responsive.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/media-inquiries-responsive.js) | None detected | N/A | Responsive utility; no GMI call. |
| 3 | [English global custody](https://www.rbcis.com/en/gmi/global-custody.page) | [mainpage.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/mainpage.js) | `/GMIService/api/Search?gmiFormId=1&count=4`<br>`/GMIService/api/Search?gmiFormId=3&count=4` | No explicit auth observed | 2 GET calls confirmed. |
| 4 | [English terms and conditions](https://www.rbcis.com/en/gmi/global-custody/terms-and-conditions.page) | [secnav.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/secnav.js) | None detected | N/A | Navigation utility; no GMI call. |
| 5 | [English tax profiles](https://www.rbcis.com/en/gmi/global-custody/tax-profiles.page) | [tax-bulletins-23.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/tax-bulletins-23.js) | `/GMIService/api/Search?gmiFormId=2&count=20`<br>`/GMIService/api/Search?gmiFormId=2` | Client-embedded Basic | 2 GET calls confirmed. |
| 6 | [English market profiles](https://www.rbcis.com/en/gmi/global-custody/market-profiles.page) | [market-profiles.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/market-profiles.js) | None detected | N/A | No GMI call detected. |
| 7 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | [jspdf.min.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/jspdf.min.js) | None detected | N/A | PDF library; no GMI call. |
| 8 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | [jspdf.plugin.autotable.min.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/jspdf.plugin.autotable.min.js) | None detected | N/A | PDF plugin; no GMI call. |
| 9 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | [holiday-calendar-26-1-bundle.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/holiday-calendar-26-1-bundle.js) | `/GMIService/api/Search?gmiFormId=5&date=self.selectedDay()`<br>`/GMIService/api/Search?gmiFormId=5` | No explicit auth observed | 2 GET calls confirmed. |
| 10 | [English holiday calendar](https://www.rbcis.com/en/gmi/global-custody/holiday-calendar.page) | [hide-holidays.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/hide-holidays.js) | None detected | N/A | Display helper; no GMI call. |
| 11 | [English updates](https://www.rbcis.com/en/gmi/global-custody/updates.page) | [updates-25.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/updates-25.js) | `/GMIService/api/Search?gmiFormId=3&count=10`<br>`/GMIService/api/Search?gmiFormId=3` | Client-embedded Basic | 2 GET calls confirmed. |
| 12 | [English GMI tax bulletins login page](https://www.rbcis.com/en/login/gmi-tax-bulletins.page) | [secnav.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/secnav.js) | None detected | N/A | Navigation utility; no GMI call. |
| 13 | [French global custody](https://www.rbcis.com/fr/gmi/global-custody.page) | [mainpage.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/mainpage.js) | `/GMIService/api/Search?gmiFormId=1&count=4`<br>`/GMIService/api/Search?gmiFormId=3&count=4` | No explicit auth observed | 2 GET calls confirmed. |
| 14 | [English GMI terms login page](https://www.rbcis.com/en/login/gmi-terms-and-conditions.page) | [secnav.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/secnav.js) | None detected | N/A | Navigation utility; no GMI call. |
| 15 | [French market newsflash](https://www.rbcis.com/fr/gmi/global-custody/market-newsflash.page) | [market-newsflash-25-fr.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/market-newsflash-25-fr.js) | `/GMIService/api/Search?gmiFormId=1&count=20`<br>`/GMIService/api/Search?gmiFormId=1` | Client-embedded Basic | 2 GET calls confirmed. |
| 16 | [French terms and conditions](https://www.rbcis.com/fr/gmi/global-custody/terms-and-conditions.page) | [secnav.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/secnav.js) | None detected | N/A | Navigation utility; no GMI call. |
| 17 | [French tax profiles](https://www.rbcis.com/fr/gmi/global-custody/tax-profiles.page) | [tax-bulletins.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/tax-bulletins.js) | `/GMIService/api/Search?gmiFormId=2&count=20`<br>`/GMIService/api/Search?gmiFormId=2` | Client-embedded Basic | 2 GET calls confirmed. |
| 18 | [French market profiles](https://www.rbcis.com/fr/gmi/global-custody/market-profiles.page) | [market-profiles.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/market-profiles.js) | None detected | N/A | No GMI call detected. |
| 19 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | [jspdf.min.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/jspdf.min.js) | None detected | N/A | PDF library; no GMI call. |
| 20 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | [jspdf.plugin.autotable.min.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/jspdf.plugin.autotable.min.js) | None detected | N/A | PDF plugin; no GMI call. |
| 21 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | [holiday-calendar-24.1-bundle.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/holiday-calendar-24.1-bundle.js) | `/GMIService/api/Search?gmiFormId=5&date=self.selectedDay()`<br>`/GMIService/api/Search?gmiFormId=5` | No explicit auth observed | 2 GET calls confirmed. |
| 22 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | [hide-holidays.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/hide-holidays.js) | None detected | N/A | Display helper; no GMI call. |
| 23 | [French holiday calendar](https://www.rbcis.com/fr/gmi/global-custody/holiday-calendar.page) | [holiday-calendar.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/holiday-calendar.js) | `/GMIService/api/Search?gmiFormId=5&date=self.selectedDay()`<br>`/GMIService/api/Search?gmiFormId=5` | No explicit auth observed | 2 GET calls; one uses jQuery shorthand. |
| 24 | [French updates](https://www.rbcis.com/fr/gmi/global-custody/updates.page) | [updates-25.js](https://www.rbcis.com/assets/rbcits/js/sub/gmi/updates-25.js) | `/GMIService/api/Search?gmiFormId=3&count=10`<br>`/GMIService/api/Search?gmiFormId=3` | Client-embedded Basic | 2 GET calls confirmed. |

## Workbook

The attached workbook contains the detailed consumer records, page-to-script mappings, script inventory, coverage, and limitations.

## Scope

Public unauthenticated pages only. Authenticated pages, server-side consumers, computed runtime loaders, and completely unlinked routes were outside scope.
