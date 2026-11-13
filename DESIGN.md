# Wrench interface system

Source: Airbnb design system color and surface tokens, adapted to an evidence review. No Airbnb marks, assets, photography, or proprietary font files are used.

## Visual thesis

Wrench reads like a private security case file: the signing and consent steps stay in a compact left rail, evidence occupies the main sheet, and a confidential transfer quote appears only after the owner reviews the dossier.

## Tokens

```css
:root {
  --color-canvas: #fffdfc;
  --color-surface: #ffffff;
  --color-surface-soft: #f7f7f7;
  --color-ink: #222222;
  --color-muted: #6a6a6a;
  --color-line: #dedede;
  --color-accent: #ff385c;
  --color-accent-active: #e00b41;
  --color-accent-soft: #fff0f3;
  --color-positive: #176b46;
  --color-positive-soft: #e9f5ee;
  --color-warning: #8a3a20;
  --color-warning-soft: #fff2e9;
  --font-display: "DM Sans", sans-serif;
  --font-body: "DM Sans", sans-serif;
  --font-mono: "DM Mono", monospace;
  --radius-control: 8px;
  --radius-panel: 14px;
  --radius-pill: 999px;
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-6: 24px;
  --space-8: 32px;
  --space-12: 48px;
  --space-16: 64px;
}
```

## Type and layout

- Interface title: 30px, 600 weight, 1.15 line height.
- Section title: 18px, 600 weight, 1.3 line height.
- Body: 14px, 400 weight, 1.55 line height.
- Data: 13px DM Mono with tabular figures.
- Layout: 240px signing rail beside a 1fr evidence sheet at wide widths; one column below 900px.
- Controls: 44px minimum height, visible focus ring, explicit disabled, loading, error, and success states.
- Evidence: plain source-linked rows, not a decorative dashboard or an unverified score.
