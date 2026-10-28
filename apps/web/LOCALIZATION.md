# Chinese interface and build verification

EgressDeck uses Simplified Chinese (`zh-CN`) for application-owned interface copy.
This includes the shell, Overview, Proxies, Subscriptions, Devices & Groups,
Rules, Infrastructure, Activity & Diagnostics, stored-inventory planning and
traffic-enrollment panels. Buttons, confirmation dialogs, form instructions,
empty/loading/error states and accessible labels are included.

## Presentation boundaries

`src/localization.ts` maps controller enums to display labels. API request values,
resource IDs, revision preconditions, CSRF headers and idempotency keys remain
unchanged. Never submit a translated label as a controller enum. Unknown future
values remain explicitly unrecognized; they are not upgraded to a success state.
Names supplied by operators, node names, addresses, URLs, protocol/product names,
capability identifiers and raw configuration retain their exact original values.

`DiagnosticMessage.vue` shows Chinese diagnostic summaries with an explicit,
collapsed original-message disclosure when upstream prose is not localized.
The original is escaped as text, not interpreted as HTML. This preserves adapter
and server detail without pretending that every possible remote message has a
verified translation. Diagnostic codes can provide more specific summaries.
No external translation service receives diagnostics or user configuration.

Browser-owned form validation is localized through delegated invalid/input/change
and reset handlers. Native constraints and page-owned custom errors stay active.
Management HTTP success, configuration application, observed readback and client
traffic verification remain separate. An audit HTTP 200 is request success;
an audit verification receipt is not proof of a client's network path.

## Development checks

From `apps/web`, with Node.js 22 and npm installed:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check:localization
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

The localization audit is part of `npm run build`, including the existing CI
production-build job. It parses Vue templates and display expressions, checking
static text, accessible names, placeholders and display literals. Protocol names,
explicit machine-value examples and raw code/diagnostic blocks are intentional
exceptions. This is a regression guard, not proof that arbitrary server/user data
contains no Latin characters. Add display-mapping unit tests when extending enums
or diagnostics. Do not hide new English UI copy behind broader allowlists.

Browser acceptance uses the repository's real Go controller test harness, real
authentication/CSRF and explicit test adapters. `e2e/localization.spec.ts` inspects
all seven pages, management editors, HTTP-error disclosure and native validation.
It captures desktop and mobile screenshots and checks horizontal overflow at
390px and 320px. The full suite additionally exercises publication, selection,
policy compilation, referenced-resource deletion guards and draft retention.
These checks do not qualify live dae/OPNsense packet paths or enable enrollment.

## Distinguish a new build from an old deployment

Every Vite build emits `dist/build-info.json` with `locale`, `sourceSha256` and
`builtAt`. The source hash covers production source, the entry HTML, dependency
manifest/lock and Vite configuration; test files are excluded. The same hash is
embedded in the HTML's `egressdeck-ui-build` meta tag and in the sidebar's
`界面版本` label (first ten characters). Development servers expose the metadata
at `/build-info.json` too. Metadata contains no runtime credentials or inventory.

After an approved deployment, compare the served `/build-info.json`, HTML meta tag
and sidebar version with the artifact being deployed. Use the same authenticated
origin as the application. A missing metadata file, an HTML fallback instead of
JSON, or a different hash means the served release has not been confirmed.
The timestamp is build time, not evidence of live deployment.

Deploy the complete reviewed `dist` directory, including its hashed assets and
metadata, using the existing deployment process. Do not hand-edit compiled JS or
copy only `index.html`. Update caches as appropriate for that process, then check
the served hash again. An old cached/released bundle and untranslated source are
separate problems; refreshing a browser cannot translate source that is still
English. Historical deployment artifacts are not replaced by a local build.
