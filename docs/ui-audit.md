# Frontend technical audit

> Audit date: 2026-08-02
> Scope: `web/admin` and `web/client` login and authenticated panel surfaces

## Health score

| Dimension | Score | Evidence / finding |
|---|---:|---|
| Accessibility | 3/4 | Form fields are label-wrapped, icon-only controls have accessible labels, focus-visible outlines are present, and semantic `main`/`nav`/`header` landmarks are used. A full automated WCAG contrast and keyboard audit still belongs in CI. |
| Performance | 2/4 | No image-heavy surface or layout-thrashing loop was found, but each production JavaScript bundle is about 1.0 MB minified and Vite reports the chunk-size warning. |
| Theming | 2/4 | Both panels share a deliberate graphite/ivory/steel-blue/state-color token base, but legacy selectors still contain repeated literal colors instead of a complete token layer. |
| Responsive design | 4/4 | Admin and Client were checked at 390×844 with Playwright; `document.documentElement.scrollWidth` equals `window.innerWidth` (390px), mobile layouts stack, tables scroll within their panels, and key controls receive 44px touch targets. |
| Anti-patterns | 4/4 | The UI uses an industrial control-room visual language: no pale-purple palette, glassmorphism, gradient text, generic dashboard hero cards, or decorative AI-style effects. |
| **Total** | **15/20** | **Good; address bundle size and consolidate remaining color literals before release.** |

## Anti-pattern verdict

**Pass.** The two panels are visually related but operationally distinct. Graphite surfaces, ivory text, steel blue actions and amber/red/green state colors provide a clear control-room hierarchy. The UI avoids the requested pale-purple treatment and does not rely on a glass-card or gradient-heavy template.

## Findings by severity

### P2 — Production bundles exceed the default chunk budget

- **Location:** `web/admin` and `web/client` Vite build output.
- **Category:** Performance.
- **Impact:** Initial JavaScript transfer and parse time can be costly on a constrained operator laptop or remote management connection.
- **Evidence:** `npm run build` reports approximately 1,022 kB and 1,031 kB minified entry chunks and the Vite 500 kB warning.
- **Recommendation:** Split low-frequency admin views and Element Plus-heavy paths with route-level `import()`; retain the current functional UI while measuring LCP/INP on the supported operator browsers.
- **Suggested command:** `/optimize`

### P2 — Color literals are not fully centralized

- **Location:** `web/admin/src/style.css`, `web/client/src/style.css`.
- **Category:** Theming.
- **Impact:** Future state-color or contrast changes can drift between the independent panels.
- **Recommendation:** Move remaining repeated surface/text/border colors into shared documented tokens, then add a CSS token policy check for new literals. Keep panel-specific tokens only where the product surfaces intentionally differ.
- **Suggested command:** `/normalize`

### P3 — Full WCAG automation is not yet part of the local gate

- **Location:** frontend CI and browser QA workflow.
- **Category:** Accessibility.
- **Impact:** Source-level labels and focus states are covered, but automated contrast, tab order, and live-page landmark checks are not yet recorded for every authenticated route.
- **Recommendation:** Add an authenticated Playwright accessibility/contrast pass in CI once a deterministic seed session is available; keep the current manual mobile check as a smoke test.
- **Suggested command:** `/harden`

## Positive findings

- Both login screens remain structurally separate: Admin never asks for a Server address, while Client keeps its Server address control behind an explicit advanced toggle.
- Authenticated surfaces expose explicit loading, error, retry, pending, failed and external-residue states rather than hiding asynchronous work.
- Keyboard focus is visible, forms use native labels, icon-only actions have `aria-label` values, and responsive tables preserve their readable minimum width inside an intentional scroll container.
- `prefers-reduced-motion: reduce` disables non-essential animation and transition timing.
- The mobile override removes the former desktop-only `body` minimum width and keeps sidebar navigation usable through horizontal scrolling.

## Recommended order

1. **[P2] `/optimize`** — split low-frequency panel views and measure operator-route loading.
2. **[P2] `/normalize`** — centralize remaining repeated color literals across the two panels.
3. **[P3] `/harden`** — add authenticated automated accessibility checks to CI.
4. **[P3] `/polish`** — perform the final visual pass after performance and token changes.
