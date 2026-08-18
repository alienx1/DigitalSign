use application_core::CoreError;
use domain::SignatureSpec;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use lopdf::{Dictionary, Document, IncrementalDocument, Object, StringFormat};
use std::io::Write;

use super::appearance;
use super::cades;
use super::image::decode_png;
use super::pkcs12;
use super::tsa::TsaConfig;

/// Reserved space (bytes) for the CMS/PKCS#7 signature, hex-encoded into
/// `/Contents`. Sized to comfortably fit our own EC-256 certs or an
/// externally-supplied RSA key (up to RSA-4096) with a small CA chain, the
/// CAdES `signingCertificateV2` attribute, AND (when `TSA_URL` is set) an
/// embedded RFC 3161 `TimeStampToken` — measured directly against 6 public
/// TSAs (FreeTSA, DigiCert, Sectigo, GlobalSign, Apple, Certum), the largest
/// (GlobalSign's) alone was ~7.7KB; padded with trailing zero bytes if
/// shorter.
const CONTENTS_RESERVED_BYTES: usize = 65536;
/// Fixed width reserved for each `/ByteRange` integer (decimal digits,
/// trailing-space padded). 10 digits covers files up to ~9.3GB.
const BYTE_RANGE_DIGIT_WIDTH: usize = 10;

/// DocMDP permission level a certifying signature declares for the whole
/// document (ISO 32000-1 Table 254's `/P`). Only ever attached to the FIRST
/// signature of a request — see `mod.rs` — since a document can have at most
/// one `/Perms/DocMDP` entry, and it must reflect what was true when it was
/// created, not something a later signature could retroactively change.
#[derive(Clone, Copy)]
pub enum DocMdpPermission {
    /// No further changes of any kind allowed — used when this is the only
    /// signature in the request.
    NoChanges,
    /// Form fill-in and additional signatures allowed, nothing else — used
    /// when more signatures follow in the same request.
    FormFillingAndSigning,
}

impl DocMdpPermission {
    fn p_value(self) -> i64 {
        match self {
            DocMdpPermission::NoChanges => 1,
            DocMdpPermission::FormFillingAndSigning => 2,
        }
    }
}

pub fn sign_one(
    document_bytes: &[u8],
    spec: &SignatureSpec,
    docmdp: Option<DocMdpPermission>,
    tsa: Option<&TsaConfig>,
) -> Result<Vec<u8>, CoreError> {
    let (pkey, cert, ca_chain) = pkcs12::unpack(&spec.key.pkcs12_der, &spec.key.derived_key)?;
    let ca_chain = match ca_chain {
        Some(chain) => chain,
        None => openssl::stack::Stack::new()
            .map_err(|e| CoreError::Signing(format!("failed to allocate cert stack: {e}")))?,
    };

    let prev =
        Document::load_mem(document_bytes).map_err(|e| CoreError::Signing(format!("invalid PDF: {e}")))?;

    let page_id = *prev
        .get_pages()
        .get(&spec.position.page)
        .ok_or_else(|| CoreError::Signing(format!("page {} not found", spec.position.page)))?;

    let root_id = prev
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|e| CoreError::Signing(format!("PDF has no /Root: {e}")))?;

    let existing_acroform_id = prev
        .get_dictionary(root_id)
        .ok()
        .and_then(|root| root.get(b"AcroForm").ok())
        .and_then(|o| o.as_reference().ok());

    let mut incr = IncrementalDocument::create_from(document_bytes.to_vec(), prev);

    let x = spec.position.x;
    let y = spec.position.y;
    let width = spec.position.width;
    let height = spec.position.height;

    // Allocated up front so its object number can name page-level resources
    // uniquely (avoids clashing with an existing page font/xobject, or with
    // another signature stamped onto the same page).
    let sig_id = incr.new_document.new_object_id();
    let xobject_name = format!("DSImg{}", sig_id.0);
    let font_name = format!("DSFont{}", sig_id.0);

    // --- appearance content: image if supplied, else text fallback. Built
    // twice: once for the signature field's own /AP (spec-correct, but
    // PDFium/Chrome's built-in viewer doesn't render Sig widget appearances —
    // https://bugs.chromium.org/p/pdfium/issues/detail?id=643), and once
    // stamped directly onto the page's content stream so it's visible in
    // every viewer regardless of that gap. ---
    let (appearance_content, appearance_resources, page_stamp_content, page_resource_entry) =
        match &spec.image {
            Some(image_bytes) => {
                let decoded = decode_png(image_bytes)?;

                let smask_id = decoded.alpha.as_ref().map(|alpha| {
                    let dict = image_xobject_dict(decoded.width, decoded.height, "DeviceGray");
                    incr.new_document
                        .add_object(lopdf::Stream::new(dict, flate_compress(alpha)))
                });

                let mut image_dict = image_xobject_dict(decoded.width, decoded.height, "DeviceRGB");
                if let Some(smask_id) = smask_id {
                    image_dict.set("SMask", Object::Reference(smask_id));
                }
                let image_id = incr
                    .new_document
                    .add_object(lopdf::Stream::new(image_dict, flate_compress(&decoded.rgb)));

                let mut xobjects = Dictionary::new();
                xobjects.set("Im0", Object::Reference(image_id));
                let mut resources = Dictionary::new();
                resources.set("XObject", Object::Dictionary(xobjects));

                (
                    appearance::content_stream_for_image(0.0, 0.0, width, height, "Im0"),
                    resources,
                    appearance::content_stream_for_image(x, y, width, height, &xobject_name),
                    ("XObject", xobject_name.clone(), Object::Reference(image_id)),
                )
            }
            None => {
                let cn = pkcs12::common_name(&cert);
                let font_dict = helvetica_font_dict();

                let mut fonts = Dictionary::new();
                fonts.set("F1", Object::Dictionary(font_dict.clone()));
                let mut resources = Dictionary::new();
                resources.set("Font", Object::Dictionary(fonts));

                (
                    appearance::content_stream_for_text(0.0, 0.0, width, height, "F1", &cn),
                    resources,
                    appearance::content_stream_for_text(x, y, width, height, &font_name, &cn),
                    ("Font", font_name.clone(), Object::Dictionary(font_dict)),
                )
            }
        };

    let mut appearance_dict = Dictionary::new();
    appearance_dict.set("Type", Object::Name(b"XObject".to_vec()));
    appearance_dict.set("Subtype", Object::Name(b"Form".to_vec()));
    appearance_dict.set("FormType", Object::Integer(1));
    appearance_dict.set(
        "BBox",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Real(width),
            Object::Real(height),
        ]),
    );
    appearance_dict.set("Resources", Object::Dictionary(appearance_resources));
    let appearance_id = incr
        .new_document
        .add_object(lopdf::Stream::new(appearance_dict, appearance_content));

    // --- signature dictionary, with placeholders for /Contents and /ByteRange ---
    let byte_range_placeholder = 10i64.pow(BYTE_RANGE_DIGIT_WIDTH as u32 - 1);

    let mut sig_dict = Dictionary::new();
    sig_dict.set("Type", Object::Name(b"Sig".to_vec()));
    sig_dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig_dict.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    sig_dict.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(byte_range_placeholder),
            Object::Integer(byte_range_placeholder),
            Object::Integer(byte_range_placeholder),
        ]),
    );
    sig_dict.set(
        "Contents",
        Object::String(vec![0u8; CONTENTS_RESERVED_BYTES], StringFormat::Hexadecimal),
    );
    sig_dict.set(
        "M",
        Object::String(format_pdf_date().into_bytes(), StringFormat::Literal),
    );
    if let Some(permission) = docmdp {
        // ISO 32000-1 §12.8.2.2 (Table 254) — a DocMDP signature reference,
        // naming the permission level (/P) this certifying signature grants
        // for the rest of the document's lifetime. No /DigestMethod/Data:
        // those exist for transforms (UR, FieldMDP) that digest a subset of
        // the document; DocMDP's scope is "everything", already covered by
        // this signature's own /ByteRange, so there's nothing extra to hash.
        let mut transform_params = Dictionary::new();
        transform_params.set("Type", Object::Name(b"TransformParams".to_vec()));
        transform_params.set("P", Object::Integer(permission.p_value()));
        transform_params.set("V", Object::Name(b"1.2".to_vec()));

        let mut sig_ref = Dictionary::new();
        sig_ref.set("Type", Object::Name(b"SigRef".to_vec()));
        sig_ref.set("TransformMethod", Object::Name(b"DocMDP".to_vec()));
        sig_ref.set("TransformParams", Object::Dictionary(transform_params));

        sig_dict.set("Reference", Object::Array(vec![Object::Dictionary(sig_ref)]));
    }
    incr.new_document.set_object(sig_id, Object::Dictionary(sig_dict));

    // --- widget annotation, linking the appearance + signature to a page position ---
    let mut ap = Dictionary::new();
    ap.set("N", Object::Reference(appearance_id));
    let mut widget = Dictionary::new();
    widget.set("Type", Object::Name(b"Annot".to_vec()));
    widget.set("Subtype", Object::Name(b"Widget".to_vec()));
    widget.set("FT", Object::Name(b"Sig".to_vec()));
    widget.set(
        "Rect",
        Object::Array(vec![
            Object::Real(x),
            Object::Real(y),
            Object::Real(x + width),
            Object::Real(y + height),
        ]),
    );
    widget.set("V", Object::Reference(sig_id));
    widget.set("P", Object::Reference(page_id));
    widget.set("F", Object::Integer(4)); // Print
    widget.set("AP", Object::Dictionary(ap));
    let widget_id = incr.new_document.add_object(Object::Dictionary(widget));

    // --- page-level content stream stamp, so the mark is visible in every
    // viewer (not just ones that render Sig widget appearances). Leading
    // newline defensively separates it from whatever the preceding /Contents
    // stream ends with, once concatenated. ---
    let mut stamp_content = Vec::with_capacity(page_stamp_content.len() + 1);
    stamp_content.push(b'\n');
    stamp_content.extend_from_slice(&page_stamp_content);
    let stamp_stream_id = incr
        .new_document
        .add_object(lopdf::Stream::new(Dictionary::new(), stamp_content));

    // --- update the page: /Annots, /Resources, /Contents ---
    incr.opt_clone_object_to_new_document(page_id)
        .map_err(|e| CoreError::Signing(e.to_string()))?;
    {
        let page_dict = incr
            .new_document
            .get_object_mut(page_id)
            .and_then(Object::as_dict_mut)
            .map_err(|e| CoreError::Signing(e.to_string()))?;

        let mut annots = match page_dict.get(b"Annots") {
            Ok(Object::Array(arr)) => arr.clone(),
            _ => Vec::new(),
        };
        annots.push(Object::Reference(widget_id));
        page_dict.set("Annots", Object::Array(annots));

        let (resource_kind, resource_name, resource_value) = page_resource_entry;
        let mut resources = match page_dict.get(b"Resources") {
            Ok(Object::Dictionary(dict)) => dict.clone(),
            _ => Dictionary::new(),
        };
        let mut kind_dict = match resources.get(resource_kind.as_bytes()) {
            Ok(Object::Dictionary(dict)) => dict.clone(),
            _ => Dictionary::new(),
        };
        kind_dict.set(resource_name.as_str(), resource_value);
        resources.set(resource_kind, Object::Dictionary(kind_dict));
        page_dict.set("Resources", Object::Dictionary(resources));

        let mut contents = match page_dict.get(b"Contents") {
            Ok(Object::Array(arr)) => arr.clone(),
            Ok(Object::Reference(r)) => vec![Object::Reference(*r)],
            _ => Vec::new(),
        };
        contents.push(Object::Reference(stamp_stream_id));
        page_dict.set("Contents", Object::Array(contents));
    }

    // --- register the signature field on /AcroForm (create it if missing) ---
    incr.opt_clone_object_to_new_document(root_id)
        .map_err(|e| CoreError::Signing(e.to_string()))?;
    match existing_acroform_id {
        Some(acroform_id) => {
            incr.opt_clone_object_to_new_document(acroform_id)
                .map_err(|e| CoreError::Signing(e.to_string()))?;
            let acroform = incr
                .new_document
                .get_object_mut(acroform_id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| CoreError::Signing(e.to_string()))?;
            let mut fields = match acroform.get(b"Fields") {
                Ok(Object::Array(arr)) => arr.clone(),
                _ => Vec::new(),
            };
            fields.push(Object::Reference(widget_id));
            acroform.set("Fields", Object::Array(fields));
            acroform.set("SigFlags", Object::Integer(3));
        }
        None => {
            let mut acroform = Dictionary::new();
            acroform.set("Fields", Object::Array(vec![Object::Reference(widget_id)]));
            acroform.set("SigFlags", Object::Integer(3));
            let acroform_id = incr.new_document.add_object(Object::Dictionary(acroform));
            let root = incr
                .new_document
                .get_object_mut(root_id)
                .and_then(Object::as_dict_mut)
                .map_err(|e| CoreError::Signing(e.to_string()))?;
            root.set("AcroForm", Object::Reference(acroform_id));
        }
    }

    // --- certify the document via this signature's /Perms/DocMDP, if this
    // is the certifying signature (see `DocMdpPermission`'s doc comment) ---
    if docmdp.is_some() {
        let mut perms = Dictionary::new();
        perms.set("DocMDP", Object::Reference(sig_id));
        let root = incr
            .new_document
            .get_object_mut(root_id)
            .and_then(Object::as_dict_mut)
            .map_err(|e| CoreError::Signing(e.to_string()))?;
        root.set("Perms", Object::Dictionary(perms));
    }

    // --- pass 1: serialize with placeholders in place ---
    let mut buf = Vec::new();
    incr.save_to(&mut buf)
        .map_err(|e| CoreError::Signing(format!("failed to save PDF: {e}")))?;

    // lopdf's incremental writer unconditionally re-emits a "%PDF-x.y" header
    // before each appended revision's objects (see `Writer::save_internal` for
    // `IncrementalDocument`). That's a syntactically harmless comment, but
    // strict validators — notably the EU DSS/PAdES validator behind
    // verifysignature.eu — read a second "%PDF-" signature as a fresh
    // document boundary and derive their own (different) reference bytes for
    // the signature, producing a spurious HASH_FAILURE even though our
    // declared /ByteRange is internally self-consistent (confirmed by
    // extracting the exact ByteRange-covered bytes and independently
    // re-verifying the CMS signature over them with OpenSSL). Neutralize
    // every such re-emitted header (skipping the real one at offset 0) with
    // an equal-length, harmless comment so no byte offsets shift and lopdf's
    // own xref table stays valid.
    for pos in find_all(&buf, b"%PDF-") {
        if pos != 0 {
            buf[pos..pos + 5].copy_from_slice(b"%----");
        }
    }

    // --- locate the placeholders in the serialized bytes ---
    //
    // Anchored on the full "/ByteRange[0 <p> <p> <p>]" text (not just the bare
    // 10-digit placeholder) so a prior signature's hex-encoded CMS blob —
    // which, being raw-ish bytes rendered as hex digits, *can* coincidentally
    // contain the same 10-digit run once it's long enough — can't be
    // mistaken for our own freshly-written placeholders. Confirmed to happen
    // in practice on a 2-signature document.
    let byte_range_anchor = format!(
        "/ByteRange[0 {p} {p} {p}]",
        p = byte_range_placeholder
    );
    let anchor_positions = find_all(&buf, byte_range_anchor.as_bytes());
    if anchor_positions.len() != 1 {
        return Err(CoreError::Signing(format!(
            "expected exactly 1 ByteRange placeholder anchor, found {}",
            anchor_positions.len()
        )));
    }
    let first_placeholder_start = anchor_positions[0] + b"/ByteRange[0 ".len();
    let field_stride = BYTE_RANGE_DIGIT_WIDTH + 1; // placeholder digits + separating space
    let byte_range_positions = [
        first_placeholder_start,
        first_placeholder_start + field_stride,
        first_placeholder_start + 2 * field_stride,
    ];

    let contents_hex_placeholder = vec![b'0'; CONTENTS_RESERVED_BYTES * 2];
    let contents_matches = find_all(&buf, &contents_hex_placeholder);
    if contents_matches.len() != 1 {
        return Err(CoreError::Signing(format!(
            "expected exactly 1 Contents placeholder, found {}",
            contents_matches.len()
        )));
    }
    let contents_hex_start = contents_matches[0];
    let contents_hex_end = contents_hex_start + CONTENTS_RESERVED_BYTES * 2;

    // --- patch in the real /ByteRange (decimal digits, trailing-space padded to
    // the same fixed width — leading zeros are legal PDF integer syntax but not
    // what any mainstream signer emits, and some strict validators mis-parse them) ---
    //
    // Both the `<` and `>` delimiters around the /Contents hex string belong in
    // the *unsigned* gap, not the signed parts either side of it — confirmed
    // empirically against a locally built `esig/dss` (the actual validation
    // engine behind the EU DSS/PAdES validators, e.g. verifysignature.eu) via
    // its own logged error: for a byte range declaring `>` as the first byte of
    // the signed second part (this crate's original behavior), DSS's own
    // extraction (`PAdESUtils.getSignatureValue`: reads bytes
    // `[a+b+1, c-1)`, a *half-open* range — not inclusive on the `c-1` end,
    // which was the first, incomplete fix here) comes up exactly one hex
    // digit short and throws `Invalid input length 8191` (odd, un-decodable).
    // Moving `c` one byte later — so `>` sits at `c-1`, inside the gap, and
    // signed part 2 starts right after it — makes that range exactly the 8192
    // hex digits, matching what's actually in `/Contents`. `pdfsig`/`openssl`
    // never notice either delimiter's placement, since both only ever trust
    // our own self-consistent declaration.
    let signed_first_part_end = contents_hex_start - 1;
    let signed_second_part_start = contents_hex_end + 1;
    let byte_range_values = [
        signed_first_part_end as i64,
        signed_second_part_start as i64,
        (buf.len() - signed_second_part_start) as i64,
    ];
    for (value, &pos) in byte_range_values.iter().zip(byte_range_positions.iter()) {
        let padded = format!("{value:<width$}", width = BYTE_RANGE_DIGIT_WIDTH);
        buf[pos..pos + BYTE_RANGE_DIGIT_WIDTH].copy_from_slice(padded.as_bytes());
    }

    // --- sign everything except the reserved Contents hex payload and its
    // surrounding `<`/`>` delimiters, per the declared /ByteRange above ---
    let mut digest_input = Vec::with_capacity(buf.len() - CONTENTS_RESERVED_BYTES * 2);
    digest_input.extend_from_slice(&buf[..signed_first_part_end]);
    digest_input.extend_from_slice(&buf[signed_second_part_start..]);

    let cms = cades::sign(&cert, &pkey, &ca_chain, &digest_input, tsa)?;
    let cms_der = cms
        .to_der()
        .map_err(|e| CoreError::Signing(format!("CMS serialization failed: {e}")))?;

    if cms_der.len() > CONTENTS_RESERVED_BYTES {
        return Err(CoreError::Signing(format!(
            "CMS signature ({} bytes) exceeds reserved space ({} bytes)",
            cms_der.len(),
            CONTENTS_RESERVED_BYTES
        )));
    }

    let mut hex = String::with_capacity(CONTENTS_RESERVED_BYTES * 2);
    for b in &cms_der {
        hex.push_str(&format!("{b:02X}"));
    }
    hex.push_str(&"0".repeat(CONTENTS_RESERVED_BYTES * 2 - hex.len()));
    buf[contents_hex_start..contents_hex_end].copy_from_slice(hex.as_bytes());

    Ok(buf)
}

fn image_xobject_dict(width: u32, height: u32, color_space: &str) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"XObject".to_vec()));
    dict.set("Subtype", Object::Name(b"Image".to_vec()));
    dict.set("Width", Object::Integer(width as i64));
    dict.set("Height", Object::Integer(height as i64));
    dict.set("ColorSpace", Object::Name(color_space.as_bytes().to_vec()));
    dict.set("BitsPerComponent", Object::Integer(8));
    dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
    dict
}

fn helvetica_font_dict() -> Dictionary {
    let mut font = Dictionary::new();
    font.set("Type", Object::Name(b"Font".to_vec()));
    font.set("Subtype", Object::Name(b"Type1".to_vec()));
    font.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
    font
}

fn flate_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("in-memory write cannot fail");
    encoder.finish().expect("in-memory finish cannot fail")
}

fn format_pdf_date() -> String {
    format!("D:{}Z", chrono::Utc::now().format("%Y%m%d%H%M%S"))
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return positions;
    }
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        if &haystack[start..start + needle.len()] == needle {
            positions.push(start);
            start += needle.len();
        } else {
            start += 1;
        }
    }
    positions
}
