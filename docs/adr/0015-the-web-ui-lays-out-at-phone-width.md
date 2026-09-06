# The web UI fits phone screens

The web wallet is often opened on a phone through a QR code or an issuance link. Every view supports a viewport down to 320px CSS width without horizontal scrolling.

Credential types can be long unbroken strings, and cards also need room for badges and actions. Credential cards use these layout rules:

- Action buttons wrap below the card content when space runs out. The card uses `flex-wrap` and the content column sets a `min-width`.
- Long tokens break at the edge of the line (`overflow-wrap: anywhere`).
- Badges move to the next line as a whole. Their labels use `white-space: nowrap`.

## Consequences

Check layout changes at 375px and 320px before release. An element that forces horizontal scrolling at those widths is a defect. Old headless Chrome clamps its window to a desktop minimum, so narrow checks use device emulation (CDP `Emulation.setDeviceMetricsOverride`) instead of `--window-size`.
