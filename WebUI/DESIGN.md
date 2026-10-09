# AI DAST WebUI Design System

## 1. Atmosphere & Identity

AI DAST is a restrained local security workspace: calm enough for sustained
operator use, explicit about trust boundaries, and dense only where the data
requires it. Its signature is the persistent live-activity rail, which keeps
connection state, scan progress, and chronological events visible without
competing with the primary task.

## 2. Color

### Palette

| Role | Token | Light | Dark | Usage |
| --- | --- | --- | --- | --- |
| Surface / primary | `--bg` | `#eef3f0` | `#101419` | Workspace background |
| Surface / panel | `--panel` | `#ffffff` | `#161c23` | Cards, forms, activity controls |
| Surface / soft | `--soft` | `#e6f0e9` | `#202e2a` | Selected and emphasized regions |
| Border / default | `--line` | `#d5dfd9` | `#29313a` | Dividers and outlines |
| Text / primary | `--text` | `#17221d` | `#e3e9ed` | Headings and body copy |
| Text / secondary | `--muted` | `#607068` | `#9fabb6` | Metadata and supporting copy |
| Accent / primary | `--accent` | `#377b55` | `#a9d7bb` | Actions, focus, live progress |
| Status / warning | `--amber` | `#916b24` | `#dfbe7f` | Caution and demo state |

### Rules

- Green communicates an active or verified state, not decoration.
- Amber communicates caution or synthetic/demo state.
- Red is reserved for errors, rejected decisions, and critical findings.
- Dark-theme secondary text targets at least 7:1 contrast where practical
  because the activity stream uses small monospace metadata.
- New colors must be introduced here before component CSS uses them.

## 3. Typography

### Scale

| Level | Size | Weight | Line height | Usage |
| --- | --- | --- | --- | --- |
| Page title | `36px` | 600 | 1.2 | Page heading |
| Section title | `19px` | 600 | 1.35 | Panel heading |
| Card title | `17px` | 600 | 1.4 | Local grouping |
| Body | `16px` | 400 | 1.6 | Default interface copy |
| Body / small | `14–15px` | 400-600 | 1.5 | Supporting text and controls |
| Caption | `12–13px` | 500 | 1.45 | Labels and metadata |
| Overline | `11px` | 600 | 1.3 | Eyebrows and section markers |
| Log body | `14px` | 400 | 1.65 | Live event messages |
| Log metadata | `12px` | 500 | 1.4 | Time, stage, and stream markers |

### Font stacks

- Primary: `Inter, "Noto Sans KR", "Malgun Gothic", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`
- Monospace: `"SFMono-Regular", Consolas, "Liberation Mono", monospace`

### Rules

- Interface text does not fall below `12px`. Short navigational overlines may
  use `11px`.
- Operational body and explanatory copy should use at least `14px`.
- Log message copy remains at least `14px`.
- Mobile breakpoints never reduce a selector below its desktop font size.
- Data-heavy numbers use tabular figures.
- Uppercase labels are limited to short metadata and use increased tracking.

## 4. Spacing & Layout

### Base unit

Spacing follows a 4px base with practical steps of 4, 8, 12, 16, 20, 24,
32, and 40px.

### Shell

- Desktop: fixed side navigation, fluid content, persistent activity rail.
- The desktop shell follows the StyleGallery
  [`fixed-sidenav-shell`](https://github.com/changeroa/StyleGallery/blob/main/patterns/viewport-shell/fixed-sidenav-shell.md)
  contract: navigation stays stable and the document remains the primary scroll
  owner.
- The content plus activity region follows
  [`main-with-rail`](https://github.com/changeroa/StyleGallery/blob/main/patterns/split-sidebar/main-with-rail.md):
  the primary task stays dominant and the rail reflows to a sheet when space is
  constrained.
- The activity rail owns its log scroll; the document owns main-content
  scroll. Controls and footer remain outside the log scroll region.
- At desktop sizes the activity rail is `320-350px`, preserving readable
  log lines and filter controls.
- At `900px` and below the activity rail becomes a fixed, collapsible bottom
  sheet so live state is reachable without scrolling through page content.
- At `660px` and below the sheet sits above the 72px bottom navigation.
- Mobile navigation includes short Korean labels beneath icons and remains
  horizontally scrollable without hiding destinations. The active destination
  scrolls into view on navigation so the current location is always visible.
- Primary content must reflow without horizontal scrolling at `390px`.

## 5. Components

### Panel

- **Structure**: section, heading cluster, optional action, body.
- **Variants**: standard, notice, error, empty.
- **States**: default, hover where actionable, focus, empty, error.
- **Accessibility**: semantic section headings and visible focus.
- **Layout**: vertical stack; the document owns scrolling.

### Status badge

- **Structure**: status dot plus concise label.
- **Variants**: live/success, demo/warning, error/critical, neutral.
- **States**: static status; no decorative animation.
- **Accessibility**: status is expressed in text as well as color.
- **Layout**: inline cluster.

### Metric card

- **Structure**: label/icon row, tabular value, contextual note.
- **Variants**: green, blue, amber, purple.
- **States**: static until a real navigation action is assigned.
- **Accessibility**: color never carries the value alone.
- **Layout**: responsive grid; values do not dominate actionable content.

### Activity rail

- **Structure**: header, source status, stage progress, search and filters,
  follow control, scrollable event stream, redaction footer. Scope collection
  events and scan events share one chronological stream but retain explicit
  `스코프 수집` and `스캔 · {단계}` source labels.
- **Variants**: desktop rail, tablet sheet, mobile sheet, collapsed.
- **States**: live, demo, reconnecting, offline, following, paused, empty,
  Scope collecting, and browser-input waiting.
- **Accessibility**: named aside, keyboard-scrollable stream, labelled filters,
  text status in addition to dots, and a labelled collapse control.
- **Motion**: no decorative motion; event arrival relies on scroll position and
  visual emphasis.
- **Layout**: fixed controls around one bounded `.log-stream` scroll owner.
- **Live cadence**: while Scope collection is active, a non-persisted
  `작업 중 · N초` row and status badge update once per second. Persisted backend
  events remain the authoritative phase history; the timer only fills quiet
  intervals so the operator can see that work is still running.

### Log entry

- **Structure**: timestamp, stage, level indicator, message.
- **Variants**: info, success, warning, error.
- **States**: default and newest-event emphasis.
- **Accessibility**: readable contrast, text level available to assistive
  technology, and wrapping for unbroken data.
- **Layout**: chronological vertical stack.

### Operator next action

- **Structure**: concise state summary, ordered workflow steps, one primary next
  action.
- **Variants**: register program, approve Scope, start scan, review findings.
- **States**: complete, current, upcoming.
- **Accessibility**: ordered list semantics, status expressed in text and icon,
  and one unambiguous button label.
- **Layout**: full-width panel before metrics on Overview; steps reflow to one
  column on narrow screens.

### Connection status

- **Structure**: status dot plus plain Korean state.
- **Variants**: demo, connected, connecting, reconnecting, no scan selected,
  offline.
- **States**: announced with `role="status"` and never left in a permanent
  loading state when no scan exists.
- **Accessibility**: state is understandable without color or implementation
  vocabulary.

### Dialog action dock

- **Structure**: required confirmation immediately above cancel and primary
  action controls.
- **States**: disabled until prerequisites pass, busy while submitting.
- **Accessibility**: remains visible at the bottom of long scrollable dialogs
  without obscuring form content.
- **Layout**: sticky to the dialog bottom with a tonal surface and top divider.

## 6. Motion & Interaction

| Type | Duration | Easing | Usage |
| --- | --- | --- | --- |
| Micro | `150ms` | ease-out | Hover and press feedback |
| Standard | `200-300ms` | ease-in-out | Sheet or panel state changes |

- Motion only communicates interaction or state.
- Layout properties are not animated.
- `prefers-reduced-motion: reduce` disables non-essential transitions.
- Pause stops auto-follow only; event ingestion continues.

## 7. Depth & Surface

The primary strategy is **borders plus tonal shift**. Panels separate through
one-pixel borders and adjacent dark or light surface tones. Shadows are
reserved for true overlays such as dialogs and the mobile activity sheet.
Cards do not receive decorative shadows.

## 8. Accessibility Constraints & Accepted Debt

### Constraints

- Target WCAG 2.2 AA; dark activity metadata aims for 7:1 contrast.
- Every interactive control has a visible focus indicator.
- Status never depends on color alone.
- Touch targets are at least 38px; primary actions target 40px or more.
- Korean and English copy must wrap without clipping or orphaned controls.
- The shipped operator interface is Korean-only. Machine identifiers,
  filenames, API paths, and standard vulnerability classifications may remain
  in their canonical form.
- The mobile activity sheet must remain collapsible and must not cover the
  bottom navigation.

### Accepted debt

| Item | Location | Why accepted | Exit |
| --- | --- | --- | --- |
| Connection vocabulary is rendered by three existing call sites | `src/App.tsx` | This pass is intentionally CSS-first and avoids restructuring the oversized application component | Extract one shared status component during the planned App decomposition |
| Log timestamps show clock time without day boundaries | `src/App.tsx` | Requires event presentation logic, not visual styling | Add date rollover markers when multi-day scan UX is implemented |
| Several legacy component colors and spacings remain literal values | `src/styles.css` | Full token migration would exceed this focused readability change | Consolidate opportunistically when each component is next changed |
