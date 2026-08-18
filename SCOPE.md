# DigitalSign — Project Scope

> Reference document for AI agents (Claude, Gemini) and human contributors working on this repo.
> Read this before proposing architecture changes or new dependencies.

## What this project is

`DigitalSign` — a Rust service that produces legally-verifiable digital signatures on PDF
documents, targeting PAdES / ISO 32000 compliance (Adobe "Signature Valid" verifiable).

## In scope

1. **Generate key pairs** — ECDSA P-256 (default) or RSA >= 2048 bits (`key_algorithm`:
   `rsa2048`/`rsa3072`/`rsa4096`) private key + X.509 certificate via `POST /ds/keypair`,
   keyed to a signer identity (`first_name`, `last_name`, `birth_day`, `birth_month`,
   `birth_year`, `country`, `national_id`). The identity is baked into the cert subject (`C` =
   ISO 3166-1 alpha-2 code, e.g. `TH`; `CN`/`GN`/`SN`; `serialNumber` = `IDC-<13-digit
   national_id>` per ETDA ขมธอ. 15-2566's subscriber certificate profile; `description` =
   birthdate as `YYYYMMDD`). `country` must be exactly 2 uppercase ASCII letters,
   `national_id` must be exactly 13 ASCII digits, and an RSA `key_algorithm` must be >= 2048
   bits, or key generation fails. The cert is **issued by a shared root CA**, not self-signed
   (see "Root CA / cert trust" below) — the PKCS#12 bundle returned to the caller includes both
   the leaf cert and the issuing root. Nothing else is persisted — the key/cert are returned to
   the caller, who is responsible for storing them.
2. **Sign PDF** — via `POST /ds/sign`, embed one or more independent PAdES/CMS signatures
   into a PDF via incremental update. Request body is `document_base64` + `users: [{
   p12_asn1_base64, derived_key, signatures: [{page,x,y,width,height,image_base64?}] }]` —
   one PKCS#12 identity per user, each able to carry multiple signature placements; applied
   in array order across all users, page number, and `(x, y)` position — e.g. page 1 signed by
   signer A's key, page 2 by signer B's key, in one request. The first signature also
   DocMDP-certifies the document (ISO 32000-1 §12.8.2.2): `/P 1` (no further changes) if it's
   the only signature in the request, `/P 2` (form fill-in + additional signatures only) if
   more follow.
3. **Place visible signature** — each signature above renders a visual appearance at its given
   `(x, y, width, height)` box on its page, drawn **twice**: once as the signature field's own
   `/AP` (spec-correct, linked to the field) and once burned directly into the page's own
   content stream at the same position (see "PDFium visibility gap" below — this duplication
   is required, not redundant). The appearance image is optional per signature (`image_base64`
   in the request, **PNG only** — 8-bit Grayscale/RGB/GrayscaleAlpha/RGBA; alpha is preserved
   via an `/SMask`) — omitting it falls back to a text-only appearance
   ("Signed by: `<cert CN>`" in Helvetica).
4. **RFC 3161 timestamping (PAdES-B-T)** — if `TSA_ENABLED=true` (see `.env.example`; `TSA_URL`
   stays configured either way, so re-enabling later doesn't mean re-typing it), every
   signature is timestamped by that TSA and the resulting `TimeStampToken` is embedded as a
   CAdES-T unsigned attribute (`id-aa-signatureTimeStampToken`) on the same CMS SignerInfo.
   Toggling it, or switching TSAs, is a config change only — no redeploy. A TSA that's down or
   errors fails the whole `/ds/sign` request (see `infrastructure::LopdfPdfSigner`'s doc
   comment for why: silently downgrading to untimestamped B-B would hide a compliance gap from
   a caller who explicitly configured a TSA because they need B-T). Verified against 6 public
   TSAs — see `.env.example`.
5. **OCSP responder** — `POST /ocsp` (RFC 6960; deliberately NOT behind `ApiKeyAuth`, same as
   any public CA's OCSP endpoint) answers whether a certificate was issued by this service's
   own root CA. No revocation database exists (nothing is persisted — see item 1), so it can
   only ever answer `good` (matches this root CA) or `unknown` (doesn't) — never `revoked`.
   Verified against `openssl ocsp`'s offline verifier (`Response verify OK`) using a real
   request built against this service's actual root CA.
6. **Auth** — every `/ds/*` route requires a valid `X-API-Key` header (see Policy decisions).
   `/ocsp` is deliberately excluded (item 5).

## Out of scope (for now)

- Long-term validation / CRL embedding (PAdES-B-LT) — the OCSP responder (below) covers the
  revocation-check half, but there's no embedding of that data into the PDF itself (`/DSS`
  dictionary) yet.
- CA integration / public trust chain (Adobe AATL) — initial target is self-signed, internal
  trust only.
- Signature verification UI (a separate concern from signing).
- Multiple API keys / per-caller identity / key rotation — one static key from env for now.

## Architecture (onion)

Cargo workspace, dependency arrows point inward only:

```
domain/src/
  document.rs         — UnsignedDocument, SignedDocument
  key.rs              — KeyPair (pkcs12_der, derived_key) — a password-protected PKCS#12
                        bundle (private key + cert) plus the random key protecting it
  identity.rs         — SignerIdentity (first_name, last_name, birth_day/month/year, country)
  signature.rs        — SignaturePosition (page, x, y, width, height)
  signature_spec.rs    — SignatureSpec (one KeyPair + one SignaturePosition + optional image
                         bytes — one placement)
  error.rs            — DomainError
  (zero external deps)

application/core/src/
  driven/          — ports infrastructure implements: KeyGenerator, PdfSigner
  driving/         — ports handler/ds calls: GenerateKeyPairUseCase, SignPdfUseCase
  error.rs         — CoreError
  (depends on domain only)

application/ds/src/
  generate_keypair.rs  — GenerateKeyPairService (impl GenerateKeyPairUseCase)
  sign_pdf.rs          — SignPdfService (impl SignPdfUseCase); takes Vec<SignatureSpec>, one per placement
  (depends on application/core + domain; never depends on infrastructure directly)

infrastructure/src/
  service/
    key_generator.rs        — OpensslKeyGenerator: real X.509 cert gen (ECDSA P-256), each
                               signer cert issued by (not self-signed against) the root CA
                               injected via `new()`
    root_ca.rs               — build_self_signed(): builds the self-signed root CA cert from
                               a caller-supplied key pair (see "Root CA / cert trust" below)
    pdf_signer/              — LopdfPdfSigner: real PAdES signing, one signature per
                               SignatureSpec, applied in array order (verified with `pdfsig`
                               — each signature independently valid after the next is added)
      mod.rs                 — LopdfPdfSigner, loops sign_one() over the signatures
      incremental.rs         — the core: lopdf::IncrementalDocument builds the new objects
                               (signature dict, widget annot, appearance Form XObject, image/
                               SMask XObjects, updated Page/AcroForm), a first pass serializes
                               with fixed-width placeholders for /ByteRange and /Contents, then
                               the exact placeholder byte offsets are located in the output and
                               patched in place: /ByteRange with real offsets (leading-zero
                               padded to the reserved width), /Contents with the hex-encoded
                               CMS SignedData (openssl::cms, DETACHED|BINARY, SHA-256, trailing-
                               zero padded) computed over the file minus that same placeholder
      pkcs12.rs              — unpacks a KeyPair's PKCS#12 bundle into (PKey, X509) for signing;
                               reads the cert's CN for the text-fallback appearance
      image.rs               — decodes the caller's PNG (png crate) into raw RGB(+alpha) samples
      appearance.rs          — content-stream builders for the image and text-fallback appearance
  middleware/       — TracingKeyGenerator, TracingPdfSigner (audit-trail decorators around the core
                      ports); ApiKeyAuth (actix-web Transform/Service checking X-API-Key); and
                      request_log (actix `middleware::from_fn` access log — one line per request:
                      method, path, status, elapsed_ms; severity follows status class: 5xx→error,
                      4xx→warn, else info; never logs headers/bodies since those may carry API keys
                      or key/PDF material). All cross-cutting adapters — port decorators and HTTP
                      middleware alike — live here.
  (depends on application/core + domain + actix-web, since ApiKeyAuth/request_log are actix middleware)

handler/ds/        — one package, two targets:
  src/routes/      — POST /ds/keypair and POST /ds/sign both take `application/json` requests
                     (`web::Json<...>`). `/ds/sign`'s `PdfSignerRequestModel` is `document_base64`
                     plus `users: Vec<UserSignatureDto>`, each `{p12_asn1_base64,derived_key,
                     signatures: Vec<SignaturePlacementDto>}` where each placement is
                     `{page,x,y,width,height,image_base64?}` — one PKCS#12 identity (`users[i]`)
                     can carry multiple signature placements. `page` is 1-indexed (matches
                     `lopdf::Document::get_pages()` keys). All base64 fields are decoded by hand
                     (`base64::engine::general_purpose::STANDARD`); a bad value returns
                     `400 Bad Request` naming the offending field, not a panic. The *response*
                     is `multipart/form-data` (hand-built — actix-multipart only parses incoming
                     multipart, it has no response-builder), a single part named `signed_pdf`
                     with `filename="signed.pdf"` and `Content-Type: application/pdf`, using a
                     fixed boundary constant (`RESPONSE_BOUNDARY` in `routes/sign.rs`) since the
                     body is one clearly-delimited binary part, not attacker-controlled multi-part
                     input. Handlers carry `#[utoipa::path(...)]`, DTOs carry `#[derive(ToSchema)]`.
  src/openapi.rs   — utoipa `ApiDoc` aggregating the above into an OpenAPI spec + the X-API-Key
                     security scheme. Purely a description of this crate's own routes — stays here,
                     unlike ApiKeyAuth, because it isn't a reusable cross-cutting adapter.
  src/lib.rs       — lib target: `scope()` assembles routes into a Scope (never imports infrastructure);
                     `swagger_ui()` serves Swagger UI at /swagger-ui/ + the spec at /api-docs/openapi.json —
                     mounted as its own service, so it's NOT behind ApiKeyAuth (that only wraps the /ds scope).
  src/main.rs      — bin target `digitalsign`: composition root. Wraps infrastructure services (including
                     ApiKeyAuth) around the routes/use-cases and starts the server — the only place that
                     calls `.wrap(infrastructure::ApiKeyAuth::new(...))`. `request_log` is wrapped on
                     `App::new()` itself (outermost, covers /ds AND /swagger-ui/), specifically OUTSIDE
                     the `/ds` scope's `ApiKeyAuth` wrap, so it also logs requests ApiKeyAuth rejects
                     with 401 — an inner wrap would never see those.
```

The bin target's own dependency list includes `infrastructure` and `application-ds` so it can construct and wire
them — but `lib.rs` itself never imports either. Rule of thumb: if `lib.rs` (the route handlers) ever needs
`use infrastructure::...` or `use application_ds::...`, that's a dependency-inversion violation — wiring belongs
in `main.rs` only.

## Tech stack

- **Language**: Rust (see `flake.nix` for the dev shell — `rustup`, `openssl`, `pkg-config`).
- **Service model**: stateless — receive input, process, return output. No database, no
  message broker, no object storage. Nothing persists across requests.
- **Web/API**: `actix-web` + `tokio` for the HTTP request/response cycle.
- **Crypto**: `openssl` crate (native OpenSSL bindings) for key/cert generation and CMS
  (`openssl::cms`) signing. Chosen over pure-Rust RustCrypto crates for maturity and
  HSM/PKCS#11 engine support. `openssl-sys` + `foreign-types` are additional direct
  dependencies (`infrastructure` only) purely so `pdf_signer/cades.rs` can add a few raw FFI
  declarations (`CMS_add1_signer`, `CMS_final`, the `CMS_CADES`/`CMS_PARTIAL` flag constants)
  that neither `openssl` nor `openssl-sys` expose — needed for the CAdES `signing-certificate-v2`
  attribute (see "Known limitations" below). Do not reach for raw FFI elsewhere without checking
  whether the safe crate already covers it; this was a deliberate, narrowly-scoped exception.
- **PDF manipulation**: `lopdf`'s `IncrementalDocument` (native incremental-update support —
  we do NOT hand-roll xref/trailer bytes) for signature dictionary, `/ByteRange`, appearance
  stream. `png` decodes signature images; `flate2` (`ZlibEncoder`) compresses image XObject
  streams for `/FlateDecode`. Avoid mixing with `printpdf` — different object models, not
  composable for this use case.
- **Serialization/logging/errors**: `serde`/`serde_json`, `tracing`/`tracing-subscriber`,
  `thiserror`, `dotenvy` (env-based config only — no config DB), `chrono` (signing timestamp
  for the PAdES `/M` field, now actually used by `LopdfPdfSigner`).

## Policy decisions

| Area | Decision |
|---|---|
| Signature standard | PAdES, baseline level PAdES-B-B (timestamping deferred, see Out of scope) |
| Hash algorithm | SHA-256 minimum |
| Key algorithm | `/ds/keypair` (key *generation*) mints ECDSA P-256 only, via `OpensslKeyGenerator`. `/ds/sign` (signing) accepts **any** PKCS#12 bundle OpenSSL can parse — RSA (PKCS#1 v1.5 / SHA-256) or EC — since `pdf_signer/pkcs12.rs::unpack()` returns an algorithm-erased `PKey<Private>` and `pdf_signer/cades.rs::sign()`'s `CMS_add1_signer` call picks the CMS `signatureAlgorithm` (`ecdsa-with-SHA256` vs. `sha256WithRSAEncryption`) based on the key itself, with no manual branching needed. Lets legacy externally-issued RSA keys sign through `/ds/sign` without being re-issued as ECDSA. |
| Key storage | Service is stateless and holds no signing identity of its own — `/ds/keypair` generates one on demand and returns it to the caller as a PKCS#12 bundle (`p12_asn1_base64`) plus the key protecting it (`derived_key`, AES-256-CBC via OpenSSL). `derived_key` is always 32 *computed* bytes rendered 1:1 as Latin-1 characters (not base64), never the literal input: with no `passphrase`/`aes_key` in the request it's 32 random bytes; if either is given, it's PBKDF2-HMAC-SHA256(seed, random salt, 100k iterations) applied to that input — so a weak caller-supplied passphrase never becomes the literal PKCS#12 password. The caller supplies `derived_key` back per signature in `/ds/sign`. Never logged, never persisted by the service. **Caveat**: because it contains raw control/non-ASCII bytes, never hand-copy/retype it between calls (terminals and UI text fields silently mangle control chars, e.g. `\r`) — always pass the JSON field through programmatically; a mismatched `derived_key` surfaces as `PKCS12_parse:mac verify failure`. `/ds/keypair`'s response also includes `derived_key_base64` (the same 32 bytes, base64-encoded) purely so it *can* be hand-copied/logged/displayed safely — `/ds/sign` still expects the raw `derived_key` form, not the base64 one. |
| Cert trust | Every signer cert is issued by a single root CA (see "Root CA / cert trust" below) — not self-signed. The root itself is still self-signed (not a real publicly-trusted CA / AATL enrollment), so DSS-style validators still won't find a trust anchor; the change is structural (one shared issuer, real chain-building) not a trust upgrade. |
| API auth | Single static key from `API_KEY` env var, checked against the `X-API-Key` header on every `/ds/*` route via `infrastructure`'s `ApiKeyAuth` middleware, wired on in `handler/ds`'s `main.rs`. Not per-caller, not rotatable yet. |
| Request body limit | actix-web's `web::Json` extractor defaults to 2MB, too small once `document_base64` + per-signature `p12_asn1_base64`/`image_base64` share one JSON body. `/ds`'s `web::JsonConfig` limit is raised via `MAX_JSON_BODY_BYTES` env var (default 25MB), set in `handler/ds`'s `main.rs` and passed into `scope()`. |

## Root CA / cert trust

Every generated signer certificate is **issued by a shared root CA**, instead of being
self-signed. Verifiers only need to decide whether to trust one root, instead of every
individual signer's own certificate — a prerequisite for real trust, though not trust itself
(the root is still self-signed; nothing here gets it into any public Trusted List).

- **Config, not code**: the root's private key and identity are 100% config-driven —
  `ROOT_CA_KEY_PATH` (any PEM EC/RSA private key file), `ROOT_CA_CN` (the self-signed root
  cert's Common Name), `ROOT_CA_VALIDITY_DAYS` (default 3650). `handler/ds`'s `main.rs` (the
  composition root) reads these at startup, loads the key, and calls
  `infrastructure::build_self_signed_ca()` to build a fresh self-signed `CA:TRUE` cert from it
  — this cert is rebuilt every startup, not persisted. None of this is a literal in source, so
  the actual key/domain backing the root can always change without a code change.
- **Current `.env`**: `ROOT_CA_KEY_PATH` points at `ssl/x1coder.icu_ecc/x1coder.icu.key` — the
  real Let's Encrypt-issued TLS private key for `x1coder.icu` (EC-256), reused as the document-
  signing root CA's key pair. **Known trade-off, chosen deliberately**: reusing one key across
  two different purposes (TLS server auth vs. document-signing CA) is generally discouraged in
  real PKI practice (compromise of one use case affects the other) — accepted here as a
  pragmatic way to anchor the root in a real, owned domain identity rather than a throwaway key.
- **What changed in the signing pipeline**: `OpensslKeyGenerator::new(root_key, root_cert)` now
  takes the root explicitly (no longer a unit struct); `generate()` sets the new signer cert's
  issuer to the root's subject and signs with the root's key (was: self-signed), adds
  `BasicConstraints: CA:FALSE` + `KeyUsage: digitalSignature, nonRepudiation` (critical), and
  bundles the root cert into the PKCS#12 via `Pkcs12Builder::ca()`. `pdf_signer/pkcs12.rs`'s
  `unpack()` now also returns that bundled CA chain; `pdf_signer/cades.rs`'s `sign()` embeds it
  into the CMS certificate set via raw `CMS_add1_cert` (not exposed by `openssl`/`openssl-sys`
  either, same FFI pattern as `CMS_add1_signer`/`CMS_CADES`), so verifiers see the full chain,
  not just the leaf.
- **Verified**: `openssl verify -CAfile <root> -partial_chain <leaf>` → `OK`; the root cert's
  public key hash matches `x1coder.icu.key`'s exactly; `openssl cms -verify -CAfile <root>`
  (no `-noverify`) on a signed PDF → `CMS Verification successful`; `pdfsig` now reports
  "Certificate issuer isn't Trusted" (found a real chain to an untrusted root) instead of the
  old self-signed "Certificate issuer is unknown" (no chain at all); 5 back-to-back
  multi-signature runs all succeeded with only one `%PDF-` header each (see "Known limitations"
  below for why that's checked).
- Not yet done: no CRL/OCSP distribution point on issued certs, no path length constraint
  beyond the implicit one from `BasicConstraints` having no `pathlen`, and the root cert itself
  isn't distributed anywhere for a verifier to actually add as a trust anchor.

## Open questions (flag before implementing)

- Root CA cert distribution: now that every signer cert chains to one root (see "Root CA / cert
  trust" above), how will verifiers actually obtain and install/trust that root cert?
- Issued certs don't yet carry an `authorityInfoAccess` extension pointing at this service's own
  `/ocsp` (see below) — a verifier that doesn't already know the URL has no automatic way to
  find it.

## Known limitations of the current `LopdfPdfSigner`

- **Resolved**: multi-signature PDFs apply each `SignatureSpec` in array order, each one a
  fresh incremental update on top of the previous. Verified with `pdfsig`: every earlier
  signature stays independently valid after later ones are added (each shows "Not total
  document signed" except the last, which covers the whole file — exactly as expected for a
  correct incremental-update chain).
- **Resolved**: `lopdf`'s `IncrementalDocument` writer unconditionally re-emits a "%PDF-x.y"
  header + binary-mark comment before each appended revision's objects
  (`Writer::save_internal`). Syntactically harmless (a `%`-comment), but strict validators —
  notably the EU DSS/PAdES validator behind verifysignature.eu — read the second "%PDF-"
  signature as a fresh document boundary and derive their own, different reference bytes for
  the signature, reporting `HASH_FAILURE`/`/ByteRange dictionary is not consistent` even though
  the declared `/ByteRange` is internally self-consistent (confirmed by extracting the exact
  ByteRange-covered bytes and independently re-verifying the CMS signature over them with
  `openssl cms -verify`, and by matching the extracted bytes' SHA-256 against the
  `messageDigest` signed attribute DSS itself reported). `incremental.rs` now neutralizes every
  re-emitted header after the real one at offset 0 (`%PDF-` → `%----`, same length, so no
  lopdf-recorded xref offset shifts) right after `incr.save_to()`. Verified against
  verifysignature.eu-style validation via manual byte/digest reconstruction, and re-checked end
  to end (single signature + 2-page/2-signature chain) with `pdfsig`.
- **Resolved**: no ESS `signing-certificate-v2` attribute (CAdES-BES's `SigningCertificateV2`,
  DSS-reported as "The signed attribute: 'signing-certificate' is absent!"). The `openssl` crate's
  safe `cms` module only wraps the one-shot `CMS_sign()` C call and doesn't expose OpenSSL's
  `CMS_CADES` flag at all (`openssl-sys` doesn't even declare the constant) — achieving it
  requires the lower-level `CMS_sign(..., CMS_PARTIAL)` → `CMS_add1_signer(..., CMS_CADES)` →
  `CMS_final(...)` sequence, which isn't exposed by the safe crate either.
  `infrastructure/src/service/pdf_signer/cades.rs` adds minimal raw `openssl-sys`-based FFI
  declarations for `CMS_add1_signer`/`CMS_final` (not present in `openssl-sys`) plus the
  `CMS_CADES`/`CMS_PARTIAL` flag constants (read directly from the linked OpenSSL 3.6.3
  headers), bridging to/from the safe `CmsContentInfo` type via `foreign_types::ForeignType`.
  Verified via `openssl cms -cmsout -print`: the signed attributes now include
  `id-smime-aa-signingCertificateV2` with a correct `ESSCertIDv2` (SHA-256 cert hash +
  `IssuerSerial`), and the signature still verifies (`openssl cms -verify`, `pdfsig`).
  **Side effect this surfaced**: the larger CMS blob (extra ~150+ bytes for the attribute) made
  a latent bug in the `/ByteRange` placeholder search occasionally reproducible on multi-signature
  documents — searching for the bare 10-digit placeholder text could coincidentally match a
  prior signature's *hex-encoded* CMS blob once it was long enough (hex digits are 0-9a-f;
  10 consecutive `0`-`9` characters can appear by chance). Fixed by anchoring the search on the
  full `"/ByteRange[0 <p> <p> <p>]"` text instead of the bare placeholder, making a coincidental
  match practically impossible. Re-verified with 15 back-to-back multi-signature runs (ECDSA
  signatures are non-deterministic, so each run produces different CMS bytes) — all succeeded.
- **Resolved**: `/ByteRange`'s declared gap excluded only `/Contents`'s hex digits — both `<` and
  `>` sat *inside* the signed parts (at `contents_hex_start - 1` and `contents_hex_end`
  respectively). Spec-legal and internally self-consistent (`pdfsig`/`openssl cms -verify` never
  cared, since both only trust our own declared `/ByteRange`), but not what mainstream PAdES
  validators assume. This took two rounds to actually fix — the first ("only `<` needs to move")
  was proven wrong by testing against a real validator, not just reasoning about source; worth
  recording *how* it was found:
  - Read `PAdESUtils.getSignatureValue` (`dss-pades`, EU DSS) and initially concluded only `<`
    needed to move into the gap (misreading its `end = secondPartStart - 1` as an inclusive
    bound). Applied that, re-signed, and re-uploaded — verifysignature.eu reported the *exact
    same* `BBB_FC_IBRV`/`HASH_FAILURE` errors. The fix was wrong; the theory needed real
    execution to falsify, not just more reading.
  - Rather than keep guessing from source, built and ran the actual EU DSS validation engine
    locally (`esig/dss-demonstrations`'s `Dockerfile`, `podman build` + `podman run`, ~3 min) —
    the same engine behind verifysignature.eu, tested directly against our own output instead of
    waiting on a remote round-trip. Its log gave the exact defect: `Invalid input length 8191`
    for a Guava hex decoder — an odd-length extraction, meaning `getSignatureValue`'s range is
    *half-open* (`[start, end)`, length `= end - start`), not inclusive as first assumed. Solving
    for that length to equal 8192 shows `>` must *also* sit inside the gap (as its last byte),
    not at the start of the signed second part.
  - Fixed by declaring the gap as `[contents_hex_start - 1, contents_hex_end + 1)` — `<` at the
    first gap byte, `>` at the last — and shrinking `digest_input`'s two slices to match.
  - Re-verified against the *same local DSS instance*: `SignatureByteRange valid="true"` for
    every signature, zero `HASH_FAILURE`/`BBB_FC_IBRV`/"not intact" messages in the container
    logs (previously reproducible in <1s), single-signature documents now validate as a clean
    `PASSED` end to end (only the expected self-signed-root trust-anchor warning remains — see
    "Root CA / cert trust" above), plus 10 back-to-back multi-signature stress runs.
  - **Separate, still-open issue found via the same local instance**: for *multi-signature*
    documents specifically, DSS still reports the earlier signature's revision as
    format-inconsistent — not a ByteRange/hash problem this time, but
    `PdfSigDictWrapper.checkConsistency`/`DefaultPdfObjectModificationsFinder` flagging an
    `Undefined`-category change (`/Catalog /Pages .../Resources/Font` and `.../Contents` on the
    *other* signer's page) introduced by the PDFium-visibility workaround below — stamping a
    later signature's appearance onto its own page's content stream is, from a strict
    incremental-update validator's view, an unclassified modification to the document after an
    earlier signature. This is a genuine tradeoff (guaranteed visibility in Chrome/Edge vs. strict
    PAdES purity across multiple signers) requiring a product decision, not a bugfix — flagged to
    the user, not resolved unilaterally.
- `/Contents` reserves a fixed 16384 bytes (hex-encoded, trailing-zero padded) for the CMS
  SignedData — comfortably fits our small self-signed EC-256 certs (now including the CAdES
  attribute) as well as an externally-supplied RSA key (up to RSA-4096) with a small CA chain
  (raised from 4096 to support legacy RSA `/ds/sign` callers); would need raising further (or
  made cert-size-aware) if certs grow beyond that (e.g. a much longer CA chain).
- `/ByteRange` reserves a fixed 10-digit width per integer (decimal digits, trailing-space
  padded — matches the iText/PDFBox/pyHanko convention) — fine up to ~9.3GB files.

## PDFium visibility gap (Chrome/Edge built-in PDF viewer)

Chrome and Edge both use PDFium, which has a long-standing, documented behavior of not
rendering `/FT /Sig` widget annotations' `/AP` appearance by default — confirmed via
[PDFium bug #643](https://bugs.chromium.org/p/pdfium/issues/detail?id=643) and
[PdfiumViewer #43](https://github.com/pvginkel/PdfiumViewer/issues/43)/[#87](https://github.com/pvginkel/PdfiumViewer/issues/87).
Poppler (`pdfsig`/`pdftoppm`) and Adobe Acrobat render it fine; PDFium-based viewers don't,
and there's no known fix from the PDF-producing side for the annotation alone.

**Workaround (implemented)**: `LopdfPdfSigner` draws the same appearance twice — once as the
Widget's `/AP` (kept for spec correctness / viewers that do honor it) and once as an ordinary
drawing operator appended to the target page's own `/Contents` (new XObject/Font resources
named uniquely per signature, e.g. `DSImg<sig object id>`, to avoid clashing with existing page
resources or other signatures on the same page). This second copy is indistinguishable from
any other page graphic, so every viewer — including Chrome/Edge — renders it unconditionally.
Trade-off: the page's content stream is genuinely modified as part of signing, not just
annotated; this is standard practice among e-signature vendors for exactly this reason.

**Further trade-off for multi-signature documents**: a strict incremental-update validator (EU
DSS — see "Known limitations" above) flags this content-stream modification as an unclassified
("Undefined" category) change when it happens in a *later* signer's revision, invalidating an
*earlier* signer's format check even though nothing about the earlier signer's own signed bytes
changed. Confirmed via a local DSS instance (see "Testing against a real PAdES validator"
below): single-signature documents validate cleanly; multi-signature documents where a later
signature's workaround touches a different page do not, under DSS's strict policy. Not yet
resolved — would require either not applying the workaround past the first signature, or
accepting the trade-off for multi-signer documents. Flag to the user before choosing.

## Testing against a real PAdES validator

Don't stop at reasoning about validator source code — a validator's exact behavior (e.g. is a
`/ByteRange` extraction range inclusive or half-open?) is only proven by running it. Reading
`esig/dss` source and building a fix from that reasoning alone produced a *confidently wrong*
fix once in this project's history (see "Known limitations" above) — it was only caught by
actually running the real engine against our output.

`esig/dss-demonstrations` ships a working `Dockerfile` that builds the actual DSS validation
engine (same one behind verifysignature.eu and similar EU DSS-based validators) from source and
serves it as a local webapp:

```sh
git clone --depth 1 https://github.com/esig/dss-demonstrations.git
cd dss-demonstrations
# podman needs fully-qualified image names; sed both FROM lines if using podman instead of docker
sed -i 's#^FROM maven:#FROM docker.io/library/maven:#; s#^FROM tomcat:#FROM docker.io/library/tomcat:#' Dockerfile
podman build -t dss-demo-local .   # ~3 min, compiles the whole DSS project
podman run -d --name dss-demo -p 18080:8080 dss-demo-local
```

Then submit a file the same way its own web UI does (fetch the CSRF token from the page first):

```sh
curl -s -c cookies.txt http://localhost:18080/validation -o page.html
CSRF=$(grep -o 'name="_csrf" content="[^"]*"' page.html | sed 's/.*content="//;s/"$//')
curl -s -b cookies.txt -c cookies.txt \
  -F "_csrf=$CSRF" -F "signedFile=@signed.pdf;type=application/pdf" \
  -F "defaultPolicy=true" -F "validationLevel=BASIC_SIGNATURES" \
  http://localhost:18080/validation -o result.html
```

`result.html` contains the same detailed report a remote validator would show. Critically,
`podman logs dss-demo` also surfaces the *exact* internal exception (e.g.
`com.google.common.io.BaseEncoding$DecodingException: Invalid input length 8191`) that a remote
validator's JSON/XML report never exposes — this is what actually pinpointed the real bug.

## Working conventions

- Don't introduce a new PDF or crypto crate without checking this doc's tech stack section
  first — the `openssl` + `lopdf` combination was chosen deliberately over higher-level
  alternatives.
- Any change to the policy table above should be confirmed with the human maintainer before
  being treated as settled.
