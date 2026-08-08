# Frontend technical audit

> Audit date: 2026-08-03
> Scope: `web/admin` and `web/client` login, authenticated panel, and modal surfaces

## Health score

| Dimension | Score | Evidence / finding |
|---|---:|---|
| Accessibility | 4/4 | The built Admin and Client entry surfaces plus deterministic authenticated navigation and create-user/Mapping/Domain dialogs pass axe WCAG 2.1 AA, unlabeled-control checks, keyboard Tab/reduced-motion checks, and the 390px overflow smoke test. |
| Performance | 3/4 | Element Plus is now imported by component instead of registering the full library. Production bundles are 225.44 kB JS / 66.13 kB CSS for Admin and 235.93 kB JS / 69.74 kB CSS for Client; Vite emits no chunk-size warning. Real-device LCP/INP measurement remains a release follow-up. |
| Theming | 3/4 | Both panels now have explicit graphite/ivory/steel-blue/state-color aliases in independent `tokens.css` files, with repeated surfaces, inputs, navigation, dialogs and borders consuming semantic variables. Intentional one-off state shades remain local. |
| Responsive design | 4/4 | Admin and Client were checked at 390×844 with Playwright; `document.documentElement.scrollWidth` equals `window.innerWidth` (390px), mobile layouts stack, tables scroll within their panels, and key controls receive 44px touch targets. |
| Anti-patterns | 4/4 | The UI uses an industrial control-room visual language: no pale-purple palette, glassmorphism, gradient text, generic dashboard hero cards, or decorative AI-style effects. |
| **Total** | **18/20** | **Excellent; retain the industrial control-room system and collect real-device performance evidence before release.** |

## Anti-pattern verdict

**Pass.** The two panels are visually related but operationally distinct. Graphite surfaces, ivory text, steel blue actions and amber/red/green state colors provide a clear control-room hierarchy. The UI avoids the requested pale-purple treatment and does not rely on a glass-card or gradient-heavy template.

## Findings by severity

### Resolved — Production bundle size

- **Location:** `web/admin` and `web/client` Vite build output.
- **Category:** Performance.
- **Impact before fix:** Initial JavaScript and CSS transfer were unnecessarily costly on a constrained operator laptop or remote management connection.
- **Fix:** Replaced full Element Plus registration and the full stylesheet with direct Dialog, Message and MessageBox imports plus component styles.
- **Evidence after fix:** Admin is 225.44 kB JS / 66.13 kB CSS and Client is 235.93 kB JS / 69.74 kB CSS; both production builds complete without the Vite 500 kB warning. The authenticated browser fixture and policy gates still pass.

### Resolved — Repeated surface and border tokens

- **Location:** `web/admin/src/style.css`, `web/client/src/style.css`.
- **Category:** Theming.
- **Impact before fix:** Repeated surface and border literals could drift between the independent panels during future contrast changes.
- **Fix:** Added independent `tokens.css` layers and moved repeated rail, panel, input, sidebar, dialog, navigation, pill, avatar, dashed-border and subtle-line values to semantic variables. One-off status and content tones remain deliberate local accents.

### P3 — Real-device performance evidence remains external

- **Location:** Release evidence, not a current UI defect.
- **Category:** Performance.
- **Impact:** A fast desktop build does not prove LCP/INP on the supported low-resource operator hardware or remote network.
- **Recommendation:** Capture LCP/INP and slow-network results on the documented Linux/operator target during the external PERF/release matrix.
- **Suggested command:** `/optimize`

### Resolved — Authenticated-route browser coverage

- **Location:** `scripts/ui-accessibility.mjs` and authenticated panel routes.
- **Category:** Accessibility hardening.
- **Evidence:** The script now intercepts a deterministic, non-secret fixture API and scans every Admin/Client navigation surface plus the Admin create-user, Client Mapping, and Client Domain dialogs.
- **Result:** `npm run test:accessibility` passes axe WCAG 2.1 AA, labels, keyboard focus/reduced motion, and 390px overflow checks for both entry and authenticated surfaces. The fixture uses `mode: simulated` and is not external runtime evidence.

### P1 fixed during this audit — Low-contrast secondary text

- **Location:** Admin/Client navigation category labels and Client Mapping/Domain metadata.
- **Category:** Accessibility.
- **Finding:** The authenticated fixture scan detected secondary text below the WCAG AA contrast target on graphite surfaces.
- **Fix:** Replaced the affected hard-coded gray values with the existing `--muted` token in both independent panels; the full authenticated scan passes after the change.

## Positive findings

- Both login screens remain structurally separate: Admin never asks for a Server address, while Client keeps its Server address control behind an explicit advanced toggle.
- Authenticated surfaces expose explicit loading, error, retry, pending, failed and external-residue states rather than hiding asynchronous work.
- Keyboard focus is visible, forms use native labels, icon-only actions have `aria-label` values, and responsive tables preserve their readable minimum width inside an intentional scroll container.
- `prefers-reduced-motion: reduce` disables non-essential animation and transition timing.
- The mobile override removes the former desktop-only `body` minimum width and keeps sidebar navigation usable through horizontal scrolling.

## Recommended order

1. **[P3] `/optimize`** — capture real-device LCP/INP and slow-network evidence in the external release matrix.
2. **[P3] `/polish`** — perform the final visual pass after external performance evidence is attached.
