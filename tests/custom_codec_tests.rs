// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for custom signature schemes on unregistered codecs.
//!
//! A custom scheme identifies itself with a codec outside `SIG_CODECS`
//! and constructs its [`Multisig`] through the existing public `Builder`
//! setters, so no dedicated custom-codec setters exist. The wire encoder
//! carries arbitrary attributes, which makes the container roundtrip
//! unchanged, and `ViewBuilder` local-codec factories supply the views on
//! built-in fallthrough.
//!
//! The tests use `Codec::Identity` (codec code 0) as the unregistered
//! demonstration slot, the convention the companion `multi-key` crate
//! uses for custom protocol keys.

use multi_codec::Codec;
use multi_sig::error::AttributesError;
use multi_sig::{
    AttrId, AttrView, Builder, ConvView, DataView, Error, LocalAttrFn, LocalConvFn, LocalDataFn,
    LocalDisclosureFn, LocalThresholdAttrFn, LocalThresholdFn, Multisig, ThresholdAttrView,
    ThresholdDisclosure, ThresholdDisclosureView, ThresholdView, ViewBuilder,
};
use multi_util::Varuint;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Attribute view that echoes the `Scheme` and `PayloadEncoding`
/// attributes the factory decoded from its `Multisig`.
struct CustomAttrView {
    scheme: u8,
    payload_encoding: Codec,
}

impl AttrView for CustomAttrView {
    fn payload_encoding(&self) -> Result<Codec, Error> {
        Ok(self.payload_encoding)
    }

    fn scheme(&self) -> Result<u8, Error> {
        Ok(self.scheme)
    }
}

/// First custom scheme sharing the `Identity` codec slot. Distinct from
/// the second scheme's view so a wrong factory branch cannot pass.
struct SchemeAAttr;

impl AttrView for SchemeAAttr {
    fn payload_encoding(&self) -> Result<Codec, Error> {
        Ok(Codec::Raw)
    }

    fn scheme(&self) -> Result<u8, Error> {
        Ok(0x2A)
    }
}

/// Second custom scheme sharing the `Identity` codec slot.
struct SchemeBAttr;

impl AttrView for SchemeBAttr {
    fn payload_encoding(&self) -> Result<Codec, Error> {
        Ok(Codec::Identity)
    }

    fn scheme(&self) -> Result<u8, Error> {
        Ok(0x2B)
    }
}

/// Data view that echoes the stored signature bytes.
struct CustomDataView(Vec<u8>);

impl DataView for CustomDataView {
    fn sig_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

/// Conversion view for the custom scheme. Its marker error identifies the
/// factory output deterministically.
struct CustomConvView;

impl ConvView for CustomConvView {
    fn to_ssh_signature(&self) -> Result<ssh_key::Signature, Error> {
        Err(Error::FailedConversion("custom scheme conv marker".into()))
    }
}

/// Threshold-attribute view that echoes the shared threshold attributes
/// the factory decoded from its `Multisig`.
struct CustomThresholdAttrView {
    threshold: usize,
    limit: usize,
    identifier: Vec<u8>,
    threshold_data: Vec<u8>,
}

impl ThresholdAttrView for CustomThresholdAttrView {
    fn threshold(&self) -> Result<usize, Error> {
        Ok(self.threshold)
    }

    fn limit(&self) -> Result<usize, Error> {
        Ok(self.limit)
    }

    fn identifier(&self) -> Result<&[u8], Error> {
        Ok(&self.identifier)
    }

    fn threshold_data(&self) -> Result<&[u8], Error> {
        Ok(&self.threshold_data)
    }
}

/// Threshold view for the custom scheme: treats the `Multisig` the
/// factory received as a single share of itself.
struct CustomThresholdView(Multisig);

impl ThresholdView for CustomThresholdView {
    fn shares(&self) -> Result<Vec<Multisig>, Error> {
        Ok(vec![self.0.clone()])
    }

    fn shares_with_disclosure(
        &self,
        _mode: ThresholdDisclosure,
        _meta_key: Option<&[u8]>,
    ) -> Result<Vec<Multisig>, Error> {
        Ok(vec![self.0.clone()])
    }

    fn add_share(&self, share: &Multisig) -> Result<Multisig, Error> {
        Ok(share.clone())
    }

    fn add_share_with_meta(
        &self,
        share: &Multisig,
        _meta_key: Option<&[u8]>,
    ) -> Result<Multisig, Error> {
        Ok(share.clone())
    }

    fn combine(&self) -> Result<Multisig, Error> {
        Ok(self.0.clone())
    }

    fn combine_with_meta(&self, _meta_key: Option<&[u8]>) -> Result<Multisig, Error> {
        Ok(self.0.clone())
    }
}

/// Disclosure view that would only answer if the built-in codec-agnostic
/// disclosure view were overridden. Its `Partial` mode differs from the
/// built-in `Full` mode so a consultation cannot go undetected.
struct CustomDisclosureView;

impl ThresholdDisclosureView for CustomDisclosureView {
    fn disclosure_mode(&self) -> Result<ThresholdDisclosure, Error> {
        Ok(ThresholdDisclosure::Partial)
    }

    fn read_threshold_params(&self, _meta_key: Option<&[u8]>) -> Result<(usize, usize), Error> {
        Ok((2, 3))
    }

    fn to_disclosure(
        &self,
        _target: ThresholdDisclosure,
        _meta_key: Option<&[u8]>,
        _current_meta_key: Option<&[u8]>,
    ) -> Result<Multisig, Error> {
        Ok(Multisig::default())
    }
}

/// Decode the `AttrId::Scheme` attribute the way built-in views do, as a
/// varuint-stored scheme value. An unset attribute yields `None`.
fn scheme_attr(ms: &Multisig) -> Option<u8> {
    let bytes = ms.attributes.get(&AttrId::Scheme)?;
    Some(*Varuint::<u8>::try_from(bytes.as_slice()).ok()?)
}

/// Decode a varuint-stored `usize` attribute. An unset attribute yields
/// `None`.
fn usize_attr(ms: &Multisig, id: AttrId) -> Option<usize> {
    let bytes = ms.attributes.get(&id)?;
    Some(*Varuint::<usize>::try_from(bytes.as_slice()).ok()?)
}

/// Decode the `AttrId::PayloadEncoding` attribute. An unset attribute
/// yields `None`.
fn payload_encoding_attr(ms: &Multisig) -> Option<Codec> {
    let bytes = ms.attributes.get(&AttrId::PayloadEncoding)?;
    Codec::try_from(bytes.as_slice()).ok()
}

/// Attribute factory for one custom scheme. It defaults to scheme `0` and
/// payload encoding `Codec::Identity` when the attributes are unset.
fn attr_factory() -> LocalAttrFn {
    Box::new(|ms: &Multisig| {
        let view: Box<dyn AttrView> = Box::new(CustomAttrView {
            scheme: scheme_attr(ms).unwrap_or(0),
            payload_encoding: payload_encoding_attr(ms).unwrap_or(Codec::Identity),
        });
        Ok(view)
    })
}

/// One factory implementation that serves two custom schemes sharing the
/// `Identity` codec slot. It branches on the `Scheme` attribute value and
/// returns the scheme-specific view.
fn branching_attr_factory() -> LocalAttrFn {
    Box::new(|ms: &Multisig| {
        let view: Box<dyn AttrView> = match scheme_attr(ms) {
            Some(0x2A) => Box::new(SchemeAAttr),
            Some(0x2B) => Box::new(SchemeBAttr),
            _ => return Err(Error::Attributes(AttributesError::MissingScheme)),
        };
        Ok(view)
    })
}

/// Attribute factory that treats an unset `Scheme` attribute as an error
/// instead of a default.
fn failing_attr_factory() -> LocalAttrFn {
    Box::new(|ms: &Multisig| {
        let scheme = scheme_attr(ms).ok_or(Error::Attributes(AttributesError::MissingScheme))?;
        let view: Box<dyn AttrView> = Box::new(CustomAttrView {
            scheme,
            payload_encoding: Codec::Identity,
        });
        Ok(view)
    })
}

/// Data factory that echoes the `SigData` attribute of the received
/// `Multisig`.
fn data_factory() -> LocalDataFn {
    Box::new(|ms: &Multisig| {
        let data = ms
            .attributes
            .get(&AttrId::SigData)
            .cloned()
            .unwrap_or_default();
        let view: Box<dyn DataView> = Box::new(CustomDataView(data));
        Ok(view)
    })
}

/// Data factory with a consultation counter and sentinel payload, used to
/// prove the factory is not consulted for a supported standard codec.
fn counting_data_factory(hits: Arc<AtomicUsize>) -> LocalDataFn {
    Box::new(move |_: &Multisig| {
        hits.fetch_add(1, Ordering::SeqCst);
        let view: Box<dyn DataView> = Box::new(CustomDataView(vec![0xEEu8]));
        Ok(view)
    })
}

/// Conversion factory that returns the marker conversion view.
fn conv_factory() -> LocalConvFn {
    Box::new(|_: &Multisig| {
        let view: Box<dyn ConvView> = Box::new(CustomConvView);
        Ok(view)
    })
}

/// Threshold-attribute factory that echoes the shared threshold
/// attributes of the received `Multisig`.
fn threshold_attr_factory() -> LocalThresholdAttrFn {
    Box::new(|ms: &Multisig| {
        let view: Box<dyn ThresholdAttrView> = Box::new(CustomThresholdAttrView {
            threshold: usize_attr(ms, AttrId::Threshold).unwrap_or(0),
            limit: usize_attr(ms, AttrId::Limit).unwrap_or(0),
            identifier: ms
                .attributes
                .get(&AttrId::ShareIdentifier)
                .cloned()
                .unwrap_or_default(),
            threshold_data: ms
                .attributes
                .get(&AttrId::ThresholdData)
                .cloned()
                .unwrap_or_default(),
        });
        Ok(view)
    })
}

/// Threshold factory that holds the received `Multisig` as its share.
fn threshold_factory() -> LocalThresholdFn {
    Box::new(|ms: &Multisig| {
        let view: Box<dyn ThresholdView> = Box::new(CustomThresholdView(ms.clone()));
        Ok(view)
    })
}

/// Disclosure factory with a consultation counter. The built-in
/// disclosure view is codec-agnostic, so this factory is never consulted.
fn disclosure_factory(hits: Arc<AtomicUsize>) -> LocalDisclosureFn {
    Box::new(move |_: &Multisig| {
        hits.fetch_add(1, Ordering::SeqCst);
        let view: Box<dyn ThresholdDisclosureView> = Box::new(CustomDisclosureView);
        Ok(view)
    })
}

/// A custom-scheme multisig on the demonstration slot, built through the
/// public `Builder` setters alone.
fn custom_ms() -> Multisig {
    Builder::new(Codec::Identity)
        .with_signature_bytes(&[0xA5u8; 32])
        .with_payload_encoding(Codec::Raw)
        .with_scheme(0x2A)
        .try_build()
        .unwrap()
}

/// A custom scheme that also stores the shared threshold attributes.
fn custom_share_ms() -> Multisig {
    Builder::new(Codec::Identity)
        .with_signature_bytes(&[0xA5u8; 32])
        .with_threshold(2)
        .with_limit(3)
        .with_identifier(b"custom-share-id")
        .with_threshold_data(b"custom-threshold-data")
        .try_build()
        .unwrap()
}

/// Extract the error from a view-build result; view trait objects carry
/// no `Debug` bound, so `unwrap_err` is unavailable there.
fn build_err<T>(result: Result<T, Error>) -> Error {
    match result {
        Ok(_) => panic!("expected an error, got Ok"),
        Err(err) => err,
    }
}

/// The custom-scheme container roundtrips through the wire format
/// losslessly: identical after decode, and byte-identical when
/// re-encoded.
#[test]
fn test_custom_codec_wire_roundtrip() {
    let ms = custom_ms();
    let bytes: Vec<u8> = ms.clone().into();
    let decoded = Multisig::try_from(bytes.as_slice()).unwrap();
    assert_eq!(decoded, ms);
    let reencoded: Vec<u8> = decoded.into();
    assert_eq!(reencoded, bytes);
}

/// The attribute factory decodes the scheme and payload-encoding
/// attributes of the received custom-scheme multisig.
#[test]
fn test_custom_attr_view_reports_scheme_and_encoding() {
    let ms = custom_ms();
    let attr = ViewBuilder::new(&ms)
        .attr()
        .with_local_codec(Codec::Identity, attr_factory())
        .build()
        .unwrap();
    assert_eq!(attr.scheme().unwrap(), 0x2A);
    assert_eq!(attr.payload_encoding().unwrap(), Codec::Raw);
}

/// The data factory echoes the signature bytes of the received
/// custom-scheme multisig.
#[test]
fn test_custom_data_view_echoes_signature_bytes() {
    let ms = custom_ms();
    let data = ViewBuilder::new(&ms)
        .data()
        .with_local_codec(Codec::Identity, data_factory())
        .build()
        .unwrap();
    assert_eq!(data.sig_bytes().unwrap(), vec![0xA5u8; 32]);
}

/// The conversion factory output is usable; its marker error identifies
/// it deterministically.
#[test]
fn test_custom_conv_view_factory_output() {
    let ms = custom_ms();
    let conv = ViewBuilder::new(&ms)
        .conv()
        .with_local_codec(Codec::Identity, conv_factory())
        .build()
        .unwrap();
    let err = conv.to_ssh_signature().unwrap_err();
    assert!(matches!(err, Error::FailedConversion(msg) if msg == "custom scheme conv marker"));
}

/// The threshold-attribute factory reads the shared threshold attributes
/// the custom scheme stores.
#[test]
fn test_custom_threshold_attr_view_reads_attributes() {
    let ms = custom_share_ms();
    let attr = ViewBuilder::new(&ms)
        .threshold_attr()
        .with_local_codec(Codec::Identity, threshold_attr_factory())
        .build()
        .unwrap();
    assert_eq!(attr.threshold().unwrap(), 2);
    assert_eq!(attr.limit().unwrap(), 3);
    assert_eq!(attr.identifier().unwrap(), &b"custom-share-id"[..]);
    assert_eq!(
        attr.threshold_data().unwrap(),
        &b"custom-threshold-data"[..]
    );
}

/// The threshold factory receives the real container: it treats the
/// custom-scheme multisig as its own single share.
#[test]
fn test_custom_threshold_view_receives_multisig() {
    let ms = custom_ms();
    let threshold = ViewBuilder::new(&ms)
        .threshold()
        .with_local_codec(Codec::Identity, threshold_factory())
        .build()
        .unwrap();
    assert_eq!(threshold.combine().unwrap(), ms);
    assert_eq!(threshold.shares().unwrap(), vec![ms.clone()]);
    assert_eq!(
        threshold
            .shares_with_disclosure(ThresholdDisclosure::Full, None)
            .unwrap(),
        vec![ms.clone()]
    );
}

/// The built-in disclosure view is codec-agnostic: the registered
/// factory is never consulted and the built-in `Full` mode answers.
#[test]
fn test_disclosure_factory_never_consulted() {
    let ms = custom_ms();
    let hits = Arc::new(AtomicUsize::new(0));
    let disclosure = ViewBuilder::new(&ms)
        .disclosure()
        .with_local_codec(Codec::Identity, disclosure_factory(hits.clone()))
        .build()
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert!(matches!(
        disclosure.disclosure_mode().unwrap(),
        ThresholdDisclosure::Full
    ));
}

/// One factory implementation serves two custom schemes that share the
/// `Identity` slot by branching on the `Scheme` attribute; each multisig
/// reaches its own scheme-specific view.
#[test]
fn test_factory_branches_on_scheme_attribute() {
    for (scheme_value, expected_encoding) in [(0x2Au8, Codec::Raw), (0x2Bu8, Codec::Identity)] {
        let ms = Builder::new(Codec::Identity)
            .with_signature_bytes(&[0xA5u8; 32])
            .with_scheme(scheme_value)
            .try_build()
            .unwrap();
        let attr = ViewBuilder::new(&ms)
            .attr()
            .with_local_codec(Codec::Identity, branching_attr_factory())
            .build()
            .unwrap();
        assert_eq!(attr.scheme().unwrap(), scheme_value);
        assert_eq!(attr.payload_encoding().unwrap(), expected_encoding);
    }
}

/// An unset `Scheme` attribute yields `None` inside the factory; this
/// factory's convention chooses its documented defaults.
#[test]
fn test_missing_scheme_default_branch() {
    let ms = Builder::new(Codec::Identity)
        .with_signature_bytes(&[0xA5u8; 32])
        .try_build()
        .unwrap();
    let attr = ViewBuilder::new(&ms)
        .attr()
        .with_local_codec(Codec::Identity, attr_factory())
        .build()
        .unwrap();
    assert_eq!(attr.scheme().unwrap(), 0);
    assert_eq!(attr.payload_encoding().unwrap(), Codec::Identity);
}

/// A factory error propagates unchanged, including a structured error
/// raised for an unset `Scheme` attribute.
#[test]
fn test_factory_error_propagates() {
    let ms = Builder::new(Codec::Identity)
        .with_signature_bytes(&[0xA5u8; 32])
        .try_build()
        .unwrap();
    let err = build_err(
        ViewBuilder::new(&ms)
            .attr()
            .with_local_codec(Codec::Identity, failing_attr_factory())
            .build(),
    );
    assert!(matches!(
        err,
        Error::Attributes(AttributesError::MissingScheme)
    ));
}

/// A factory registered for a standard codec with built-in support is
/// never consulted; the built-in view answers with the real data.
#[test]
fn test_factory_not_consulted_for_standard_codec() {
    let ms = Builder::new(Codec::EddsaMsig)
        .with_signature_bytes(&[0xA5u8; 32])
        .try_build()
        .unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let data = ViewBuilder::new(&ms)
        .data()
        .with_local_codec(Codec::EddsaMsig, counting_data_factory(hits.clone()))
        .build()
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(data.sig_bytes().unwrap(), vec![0xA5u8; 32]);
}

/// The custom-scheme container passes a JSON roundtrip unchanged: the
/// human-readable serde path encodes attributes by name.
#[cfg(feature = "serde")]
#[test]
fn test_custom_codec_serde_roundtrip() {
    let ms = custom_ms();
    let text = serde_json::to_string(&ms).unwrap();
    let decoded: Multisig = serde_json::from_str(&text).unwrap();
    assert_eq!(decoded, ms);
}
