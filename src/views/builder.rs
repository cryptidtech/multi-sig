// SPDX-License-Identifier: Apache-2.0
//! Builder-pattern construction of the read-only [`Multisig`] view types.
//!
//! [`ViewBuilder`](crate::views::builder::ViewBuilder) replaces direct trait-method view access with a fluent
//! shape. It serves two purposes:
//!
//! 1. Standard codecs reach their built-in views through the same dispatch
//!    core that backs the `Views` extension trait.
//! 2. Signature schemes that the crate does not standardize yet carry a codec
//!    outside [`SIG_CODECS`](crate::SIG_CODECS) and reach their views through
//!    caller-supplied local-codec factories (issue #3).
//!
//! # Flow
//!
//! [`ViewBuilder::new`](crate::views::builder::ViewBuilder::new) returns an
//! [unselected](crate::views::builder::Unselected) builder. A kind selector
//! transitions the builder into the requested view kind. A kind-selected
//! builder optionally registers a local-codec factory with
//! [`ViewBuilder::with_local_codec`](crate::views::builder::ViewBuilder::with_local_codec)
//! and finishes with
//! [`ViewBuilder::build`](crate::views::builder::ViewBuilder::build).
//!
//! # Example
//!
//! ```
//! use multi_sig::prelude::*;
//!
//! // A custom scheme carries a codec outside `SIG_CODECS`. The convention
//! // uses the `Identity` slot (codec code 0) for demonstration.
//! let ms = Builder::new(Codec::Identity)
//!     .with_signature_bytes(&[0u8; 8])
//!     .try_build()
//!     .unwrap();
//!
//! struct Custom;
//!
//! impl AttrView for Custom {
//!     fn payload_encoding(&self) -> Result<Codec, Error> {
//!         Ok(Codec::Identity)
//!     }
//!     fn scheme(&self) -> Result<u8, Error> {
//!         Ok(0x2A)
//!     }
//! }
//!
//! let view = ViewBuilder::new(&ms)
//!     .attr()
//!     .with_local_codec(Codec::Identity, Box::new(|_ms| Ok(Box::new(Custom))))
//!     .build()
//!     .unwrap();
//! assert_eq!(view.scheme().unwrap(), 0x2A);
//! ```
//!
//! # Dispatch order
//!
//! `build` consults the built-in codec dispatch first. Only when it reports
//! [`AttributesError::UnsupportedCodec`](crate::error::AttributesError::UnsupportedCodec)
//! for the codec carried by the `Multisig` is a registered local factory
//! consulted. A factory registered for any other codec is ignored and the
//! original error propagates. A built-in view is therefore never overridden
//! by a factory.
//!
//! The `disclosure` kind is the exception among kinds: its view is
//! codec-agnostic and always built in, so a local factory for that kind is
//! never consulted.
//!
//! # Factory contract
//!
//! A factory is a boxed `Fn(&Multisig) -> Result<Box<dyn ViewTrait>, Error>`
//! closure that must hold the `Send + Sync + 'static` bounds in its type
//! alias and must not capture borrows. Errors from a factory propagate
//! unchanged. A repeat `with_local_codec` call for the same kind replaces
//! the earlier factory: the last registration wins.
//!
//! A factory may return a view that borrows the `Multisig`. A small
//! lifetime-parameterized helper function keeps closure inference simple
//! for that case; see the unit tests for the pattern.
//!
//! The demonstration slot for a custom scheme is [`Codec::Identity`]
//! (codec code 0), which no built-in dispatch table covers. Schemes that
//! share a slot disambiguate through attributes inside the factory.
//!
//! # Cross-crate alignment
//!
//! `multi_key::ViewBuilder` carries the same fluent-selector shape for the
//! companion `multi-key` crate; `multi_key::Views` is a separate, unrelated
//! trait. This module also records the documented deviation from the issue
//! #3 callback sketch: this crate has six view traits and no single `View`
//! trait, so the type-safe realization of the callback capability is a
//! per-kind fluent selector plus a per-kind typed factory.

use crate::{
    AttrView, ConvView, DataView, Error, Multisig, ThresholdAttrView, ThresholdDisclosureView,
    ThresholdView, error::AttributesError, views::dispatch,
};
use multi_codec::Codec;
use multi_util::CodecInfo;
use std::marker::PhantomData;

/// Sealing for the [`ViewKind`] trait. Kept private so downstream code
/// cannot implement view kinds.
mod sealed {
    /// Sealed trait that prevents downstream implementations of view kinds.
    #[doc(hidden)]
    pub trait Sealed {}
}

/// Identifies the kind of view a [`ViewBuilder`] can build.
///
/// Sealed: [`AttrKind`], [`DataKind`], [`ConvKind`], [`ThresholdAttrKind`],
/// [`ThresholdKind`], [`DisclosureKind`], and [`Unselected`] are the only
/// implementors. Adding a view kind is a breaking change.
pub trait ViewKind: sealed::Sealed {
    /// Boxed local-codec factory type accepted by
    /// [`ViewBuilder::with_local_codec`] for this view kind.
    #[doc(hidden)]
    type Factory;
}

/// Marker for the builder state before any view kind is selected. Only the
/// kind selectors are available in this state; `with_local_codec` and
/// `build` become available after a selector runs.
pub struct Unselected;

/// Marker for the [`AttrView`] view kind, selected by [`ViewBuilder::attr`].
pub struct AttrKind;

/// Marker for the [`DataView`] view kind, selected by [`ViewBuilder::data`].
pub struct DataKind;

/// Marker for the [`ConvView`] view kind, selected by [`ViewBuilder::conv`].
pub struct ConvKind;

/// Marker for the [`ThresholdAttrView`] view kind, selected by
/// [`ViewBuilder::threshold_attr`].
pub struct ThresholdAttrKind;

/// Marker for the [`ThresholdView`] view kind, selected by
/// [`ViewBuilder::threshold`].
pub struct ThresholdKind;

/// Marker for the [`ThresholdDisclosureView`] view kind, selected by
/// [`ViewBuilder::disclosure`].
pub struct DisclosureKind;

/// Boxed local-codec factory for the attributes view kind.
pub type LocalAttrFn = Box<
    dyn for<'a> Fn(&'a Multisig) -> Result<Box<dyn AttrView + 'a>, Error> + Send + Sync + 'static,
>;

/// Boxed local-codec factory for the data view kind.
pub type LocalDataFn = Box<
    dyn for<'a> Fn(&'a Multisig) -> Result<Box<dyn DataView + 'a>, Error> + Send + Sync + 'static,
>;

/// Boxed local-codec factory for the conversion view kind.
pub type LocalConvFn = Box<
    dyn for<'a> Fn(&'a Multisig) -> Result<Box<dyn ConvView + 'a>, Error> + Send + Sync + 'static,
>;

/// Boxed local-codec factory for the threshold attributes view kind.
pub type LocalThresholdAttrFn = Box<
    dyn for<'a> Fn(&'a Multisig) -> Result<Box<dyn ThresholdAttrView + 'a>, Error>
        + Send
        + Sync
        + 'static,
>;

/// Boxed local-codec factory for the threshold view kind.
pub type LocalThresholdFn = Box<
    dyn for<'a> Fn(&'a Multisig) -> Result<Box<dyn ThresholdView + 'a>, Error>
        + Send
        + Sync
        + 'static,
>;

/// Boxed local-codec factory for the threshold disclosure view kind. Stored
/// only for API symmetry: the built-in disclosure view is codec-agnostic, so
/// this factory is never consulted.
pub type LocalDisclosureFn = Box<
    dyn for<'a> Fn(&'a Multisig) -> Result<Box<dyn ThresholdDisclosureView + 'a>, Error>
        + Send
        + Sync
        + 'static,
>;

impl sealed::Sealed for Unselected {}

impl sealed::Sealed for AttrKind {}

impl sealed::Sealed for DataKind {}

impl sealed::Sealed for ConvKind {}

impl sealed::Sealed for ThresholdAttrKind {}

impl sealed::Sealed for ThresholdKind {}

impl sealed::Sealed for DisclosureKind {}

impl ViewKind for Unselected {
    /// The unselected state registers no factory, so the slot type is
    /// never instantiated.
    type Factory = ();
}

impl ViewKind for AttrKind {
    type Factory = LocalAttrFn;
}

impl ViewKind for DataKind {
    type Factory = LocalDataFn;
}

impl ViewKind for ConvKind {
    type Factory = LocalConvFn;
}

impl ViewKind for ThresholdAttrKind {
    type Factory = LocalThresholdAttrFn;
}

impl ViewKind for ThresholdKind {
    type Factory = LocalThresholdFn;
}

impl ViewKind for DisclosureKind {
    type Factory = LocalDisclosureFn;
}

/// Builder for the read-only view types of a [`Multisig`].
///
/// See the module documentation for the full contract. The second type
/// parameter tracks the selected view kind at the type level:
///
/// - [`ViewBuilder::attr`], [`ViewBuilder::data`], [`ViewBuilder::conv`],
///   [`ViewBuilder::threshold_attr`], [`ViewBuilder::threshold`], and
///   [`ViewBuilder::disclosure`] each transition an
///   [unselected](Unselected) builder into a kind-selected one.
/// - A kind-selected builder accepts `.with_local_codec` and finishes with
///   `.build`.
/// - The builder itself is `Send + Sync` when its factory type is. The
///   returned `Box<dyn ViewTrait + 'ms>` carries no `Send`/`Sync` bound;
///   the docs of the view traits must not promise more.
///
/// Dispatch order: built-in view first, local factory second (on
/// `AttributesError::UnsupportedCodec` fallthrough only), error last.
pub struct ViewBuilder<'ms, K: ViewKind> {
    ms: &'ms Multisig,
    kind: PhantomData<K>,
    local: Option<(Codec, K::Factory)>,
}

impl<'ms> ViewBuilder<'ms, Unselected> {
    /// Start building a view for `ms`.
    pub fn new(ms: &'ms Multisig) -> Self {
        Self {
            ms,
            kind: PhantomData,
            local: None,
        }
    }

    /// Re-select a view kind from the held `Multisig` reference.
    fn select<K: ViewKind>(self) -> ViewBuilder<'ms, K> {
        ViewBuilder {
            ms: self.ms,
            kind: PhantomData,
            local: None,
        }
    }

    /// Select the attributes view kind; `build` then returns
    /// `Result<Box<dyn AttrView + 'ms>, Error>`.
    pub fn attr(self) -> ViewBuilder<'ms, AttrKind> {
        self.select()
    }

    /// Select the data view kind; `build` then returns
    /// `Result<Box<dyn DataView + 'ms>, Error>`.
    pub fn data(self) -> ViewBuilder<'ms, DataKind> {
        self.select()
    }

    /// Select the conversion view kind; `build` then returns
    /// `Result<Box<dyn ConvView + 'ms>, Error>`.
    pub fn conv(self) -> ViewBuilder<'ms, ConvKind> {
        self.select()
    }

    /// Select the threshold attributes view kind; `build` then returns
    /// `Result<Box<dyn ThresholdAttrView + 'ms>, Error>`.
    pub fn threshold_attr(self) -> ViewBuilder<'ms, ThresholdAttrKind> {
        self.select()
    }

    /// Select the threshold view kind; `build` then returns
    /// `Result<Box<dyn ThresholdView + 'ms>, Error>`.
    pub fn threshold(self) -> ViewBuilder<'ms, ThresholdKind> {
        self.select()
    }

    /// Select the threshold disclosure view kind; `build` then returns
    /// `Result<Box<dyn ThresholdDisclosureView + 'ms>, Error>`.
    pub fn disclosure(self) -> ViewBuilder<'ms, DisclosureKind> {
        self.select()
    }
}

macro_rules! view_kind_api {
    ($kind:ident, $factory:ident, $view:ident, $dispatch:ident) => {
        impl<'ms> ViewBuilder<'ms, $kind> {
            /// Register a local-codec factory for this view kind.
            ///
            /// `factory` must be the boxed HRTB form named by this kind's
            /// `Local*Fn` type alias: a closure that receives the
            /// `Multisig`, returns `Result<Box<dyn ViewTrait>, Error>`, and
            /// holds `Send + Sync + 'static`. It must not capture borrows.
            ///
            /// A repeat call replaces the earlier factory: the last
            /// registration wins.
            pub fn with_local_codec(mut self, codec: Codec, factory: $factory) -> Self {
                self.local = Some((codec, factory));
                self
            }

            /// Build the requested view.
            ///
            /// The built-in codec dispatch runs first. On
            /// `AttributesError::UnsupportedCodec` fallthrough with the codec
            /// carried by the `Multisig`, a registered local-codec factory
            /// runs, and its output or error is returned unchanged. A
            /// factory registered for another codec is ignored, and the
            /// dispatch error propagates unchanged. The `disclosure` kind is
            /// codec-agnostic, so its local factory is never consulted.
            pub fn build(self) -> Result<Box<dyn $view + 'ms>, Error> {
                let ms = self.ms;
                match dispatch::$dispatch(ms) {
                    Ok(view) => Ok(view),
                    Err(err @ Error::Attributes(AttributesError::UnsupportedCodec(_))) => {
                        match &self.local {
                            Some((codec, factory)) if *codec == ms.codec() => factory(ms),
                            _ => Err(err),
                        }
                    }
                    Err(err) => Err(err),
                }
            }
        }
    };
}

view_kind_api!(AttrKind, LocalAttrFn, AttrView, dispatch_attr_view);
view_kind_api!(DataKind, LocalDataFn, DataView, dispatch_data_view);
view_kind_api!(ConvKind, LocalConvFn, ConvView, dispatch_conv_view);
view_kind_api!(
    ThresholdAttrKind,
    LocalThresholdAttrFn,
    ThresholdAttrView,
    dispatch_threshold_attr_view
);
view_kind_api!(
    ThresholdKind,
    LocalThresholdFn,
    ThresholdView,
    dispatch_threshold_view
);
view_kind_api!(
    DisclosureKind,
    LocalDisclosureFn,
    ThresholdDisclosureView,
    dispatch_disclosure_view
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttrId, Builder, SIG_CODECS, SIG_SHARE_CODECS, ThresholdDisclosure};
    use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};

    /// Sentinel attribute view produced by test factories.
    struct SchemeAttr(u8);

    impl AttrView for SchemeAttr {
        fn payload_encoding(&self) -> Result<Codec, Error> {
            Ok(Codec::Identity)
        }

        fn scheme(&self) -> Result<u8, Error> {
            Ok(self.0)
        }
    }

    /// Sentinel data view for factory tests; echoes the stored bytes.
    struct BytesDataView(Vec<u8>);

    impl DataView for BytesDataView {
        fn sig_bytes(&self) -> Result<Vec<u8>, Error> {
            Ok(self.0.clone())
        }
    }

    /// Sentinel conversion view; every method carries a distinctive marker.
    struct FactoryConvView;

    impl ConvView for FactoryConvView {
        fn to_ssh_signature(&self) -> Result<ssh_key::Signature, Error> {
            Err(Error::FailedConversion("factory conv marker".into()))
        }
    }

    /// Sentinel threshold attributes view for factory tests.
    struct ThresholdAttrSentinel(Vec<u8>);

    impl ThresholdAttrView for ThresholdAttrSentinel {
        fn threshold(&self) -> Result<usize, Error> {
            Ok(6)
        }

        fn limit(&self) -> Result<usize, Error> {
            Ok(9)
        }

        fn identifier(&self) -> Result<&[u8], Error> {
            Ok(&self.0)
        }

        fn threshold_data(&self) -> Result<&[u8], Error> {
            Ok(&self.0)
        }
    }

    /// Sentinel threshold view for factory tests; carries its own share.
    struct ThresholdSentinel(Multisig);

    impl ThresholdView for ThresholdSentinel {
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

    /// Sentinel disclosure view for the never-consulted factory test. Its
    /// `disclosure_mode` differs from the built-in answer so that a
    /// consultation cannot go undetected.
    struct DisclosureSentinel;

    impl ThresholdDisclosureView for DisclosureSentinel {
        fn disclosure_mode(&self) -> Result<ThresholdDisclosure, Error> {
            Ok(ThresholdDisclosure::Partial)
        }

        fn read_threshold_params(&self, _meta_key: Option<&[u8]>) -> Result<(usize, usize), Error> {
            Ok((6, 9))
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

    /// Data view bound to its source `Multisig`, proving the factory HRTB
    /// accepts views that borrow it.
    struct BorrowedDataView<'ms>(&'ms Multisig);

    impl DataView for BorrowedDataView<'_> {
        fn sig_bytes(&self) -> Result<Vec<u8>, Error> {
            Ok(self.0.message.clone())
        }
    }

    /// Attribute factory with a sentinel scheme.
    fn scheme_attr_factory(scheme: u8) -> LocalAttrFn {
        Box::new(move |_: &Multisig| {
            let attr: Box<dyn AttrView> = Box::new(SchemeAttr(scheme));
            Ok(attr)
        })
    }

    /// Data factory that echoes the signature bytes of the `Multisig` it
    /// receives.
    fn ms_data_factory() -> LocalDataFn {
        Box::new(|ms: &Multisig| {
            let data = ms
                .attributes
                .get(&AttrId::SigData)
                .cloned()
                .unwrap_or_default();
            let view: Box<dyn DataView> = Box::new(BytesDataView(data));
            Ok(view)
        })
    }

    /// A multisig with the unregistered custom codec slot.
    fn custom_ms() -> Multisig {
        Builder::new(Codec::Identity)
            .with_signature_bytes(&[0u8; 64])
            .with_scheme(0x2B)
            .try_build()
            .unwrap()
    }

    /// A multisig for a codec that has a built-in data view but no
    /// threshold views.
    fn es256k_ms() -> Multisig {
        Builder::new(Codec::Es256KMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap()
    }

    /// Extract the error from a view-build result; view trait objects carry
    /// no `Debug` bound, so `unwrap_err` is unavailable here.
    fn build_err<T>(result: Result<T, Error>) -> Error {
        match result {
            Ok(_) => panic!("expected an error, got Ok"),
            Err(err) => err,
        }
    }

    #[test]
    fn test_sig_codecs_data_view_dispatch() {
        for codec in SIG_CODECS {
            let ms = Builder::new(codec)
                .with_signature_bytes(&[0u8; 64])
                .try_build()
                .unwrap();
            let result = ViewBuilder::new(&ms).data().build();
            assert!(
                result.is_ok(),
                "SIG_CODECS entry {codec:?} does not dispatch a data view through the builder (error kind {:?})",
                result.err().map(|e| e.to_string())
            );
        }
    }

    #[test]
    fn test_sig_share_codecs_threshold_attr_dispatch() {
        for codec in SIG_SHARE_CODECS {
            let ms = Builder::new(codec)
                .with_signature_bytes(&[0u8; 64])
                .try_build()
                .unwrap();
            let result = ViewBuilder::new(&ms).threshold_attr().build();
            assert!(
                result.is_ok(),
                "SIG_SHARE_CODECS entry {codec:?} does not dispatch a threshold-attribute view through the builder (error kind {:?})",
                result.err().map(|e| e.to_string())
            );
        }
    }

    #[test]
    fn test_representative_kinds_build() {
        let ms = Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();

        assert!(ViewBuilder::new(&ms).attr().build().is_ok());
        let data = ViewBuilder::new(&ms).data().build().unwrap();
        assert_eq!(data.sig_bytes().unwrap(), vec![0u8; 64]);
        assert!(ViewBuilder::new(&ms).conv().build().is_ok());

        // A share codec that carries threshold attributes.
        let share = Builder::new(Codec::Bls12381G2ShareMsig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        assert!(ViewBuilder::new(&share).threshold_attr().build().is_ok());

        // A combined BLS codec that carries share accumulation.
        let combined = Builder::new(Codec::Bls12381G1Msig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        assert!(ViewBuilder::new(&combined).threshold().build().is_ok());

        // The disclosure view builds for any codec.
        assert!(ViewBuilder::new(&combined).disclosure().build().is_ok());
    }

    #[test]
    fn test_unsupported_codec_without_factory() {
        let ms = es256k_ms();
        let err = build_err(ViewBuilder::new(&ms).threshold().build());
        assert!(matches!(
            err,
            Error::Attributes(AttributesError::UnsupportedCodec(Codec::Es256KMsig))
        ));
    }

    #[test]
    fn test_custom_codec_factories_return_output() {
        let ms = custom_ms();

        // Attributes kind: the factory output carries the sentinel scheme.
        let attr = ViewBuilder::new(&ms)
            .attr()
            .with_local_codec(Codec::Identity, scheme_attr_factory(0x2A))
            .build()
            .unwrap();
        assert_eq!(attr.scheme().unwrap(), 0x2A);

        // Data kind: the factory receives the multisig and echoes its data.
        let data = ViewBuilder::new(&ms)
            .data()
            .with_local_codec(Codec::Identity, ms_data_factory())
            .build()
            .unwrap();
        assert_eq!(data.sig_bytes().unwrap(), vec![0u8; 64]);

        // Threshold attributes kind.
        let threshold_attr = ViewBuilder::new(&ms)
            .threshold_attr()
            .with_local_codec(
                Codec::Identity,
                Box::new(move |_: &Multisig| {
                    let view: Box<dyn ThresholdAttrView> =
                        Box::new(ThresholdAttrSentinel(vec![7u8]));
                    Ok(view)
                }),
            )
            .build()
            .unwrap();
        assert_eq!(threshold_attr.threshold().unwrap(), 6);
        assert_eq!(threshold_attr.limit().unwrap(), 9);
        assert_eq!(threshold_attr.identifier().unwrap(), &[7u8]);

        // Threshold kind. The sentinel carries its own deterministic share.
        let threshold = ViewBuilder::new(&ms)
            .threshold()
            .with_local_codec(
                Codec::Identity,
                Box::new(|_: &Multisig| {
                    let view: Box<dyn ThresholdView> = Box::new(ThresholdSentinel(custom_ms()));
                    Ok(view)
                }),
            )
            .build()
            .unwrap();
        assert_eq!(threshold.combine().unwrap(), custom_ms());
    }

    #[test]
    fn test_custom_codec_conv_factory() {
        let ms = custom_ms();
        let conv = ViewBuilder::new(&ms)
            .conv()
            .with_local_codec(
                Codec::Identity,
                Box::new(|_: &Multisig| {
                    let view: Box<dyn ConvView> = Box::new(FactoryConvView);
                    Ok(view)
                }),
            )
            .build()
            .unwrap();
        // The built box is the factory's view: its marker error identifies it.
        let err = conv.to_ssh_signature().unwrap_err();
        assert!(matches!(err, Error::FailedConversion(msg) if msg == "factory conv marker"));
    }

    #[test]
    fn test_factory_error_propagates() {
        let ms = custom_ms();
        let result = ViewBuilder::new(&ms)
            .attr()
            .with_local_codec(
                Codec::Identity,
                Box::new(|_: &Multisig| -> Result<Box<dyn AttrView>, Error> {
                    Err(Error::FailedConversion("factory boom".into()))
                }),
            )
            .build();
        let err = build_err(result);
        assert!(matches!(err, Error::FailedConversion(msg) if msg == "factory boom"));
    }

    #[test]
    fn test_builtin_view_wins_over_factory() {
        let ms = es256k_ms();
        let hits = Arc::new(AtomicUsize::new(0));
        let data = ViewBuilder::new(&ms)
            .data()
            .with_local_codec(Codec::Es256KMsig, ms_data_factory_with_hits(hits.clone()))
            .build()
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        // The built-in view holds the real signature data, not the sentinel.
        assert_eq!(data.sig_bytes().unwrap(), vec![0u8; 64]);
    }

    /// Data factory with a call counter and a sentinel payload.
    fn ms_data_factory_with_hits(hits: Arc<AtomicUsize>) -> LocalDataFn {
        Box::new(move |_: &Multisig| {
            hits.fetch_add(1, Ordering::SeqCst);
            let view: Box<dyn DataView> = Box::new(BytesDataView(vec![0xEEu8]));
            Ok(view)
        })
    }

    #[test]
    fn test_factory_for_other_codec_ignored() {
        let ms = es256k_ms();
        let result = ViewBuilder::new(&ms)
            .threshold()
            .with_local_codec(
                Codec::Identity,
                Box::new(|_: &Multisig| {
                    let view: Box<dyn ThresholdView> = Box::new(ThresholdSentinel(custom_ms()));
                    Ok(view)
                }),
            )
            .build();
        let err = build_err(result);
        assert!(matches!(
            err,
            Error::Attributes(AttributesError::UnsupportedCodec(Codec::Es256KMsig))
        ));
    }

    #[test]
    fn test_last_registration_wins() {
        let ms = custom_ms();
        let attr = ViewBuilder::new(&ms)
            .attr()
            .with_local_codec(Codec::Identity, scheme_attr_factory(0x01))
            .with_local_codec(Codec::Identity, scheme_attr_factory(0x02))
            .build()
            .unwrap();
        assert_eq!(attr.scheme().unwrap(), 0x02);
    }

    #[test]
    fn test_disclosure_factory_never_consulted() {
        let ms = custom_ms();
        let hits = Arc::new(AtomicUsize::new(0));
        let disclosure = ViewBuilder::new(&ms)
            .disclosure()
            .with_local_codec(
                Codec::Identity,
                Box::new({
                    let hits = hits.clone();
                    move |_: &Multisig| {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let view: Box<dyn ThresholdDisclosureView> = Box::new(DisclosureSentinel);
                        Ok(view)
                    }
                }),
            )
            .build()
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        // The built-in disclosure view answers, not the sentinel.
        assert!(matches!(
            disclosure.disclosure_mode().unwrap(),
            ThresholdDisclosure::Full
        ));
    }

    #[test]
    fn test_builder_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send_sync_value<T: Send + Sync>(_: &T) {}

        assert_send_sync::<ViewBuilder<'static, Unselected>>();
        assert_send_sync::<ViewBuilder<'static, AttrKind>>();
        assert_send_sync::<ViewBuilder<'static, DataKind>>();
        assert_send_sync::<ViewBuilder<'static, ConvKind>>();
        assert_send_sync::<ViewBuilder<'static, ThresholdAttrKind>>();
        assert_send_sync::<ViewBuilder<'static, ThresholdKind>>();
        assert_send_sync::<ViewBuilder<'static, DisclosureKind>>();

        let ms = custom_ms();
        let plain = ViewBuilder::new(&ms).attr();
        let with_factory = ViewBuilder::new(&ms)
            .attr()
            .with_local_codec(Codec::Identity, scheme_attr_factory(0x01));
        assert_send_sync_value(&plain);
        assert_send_sync_value(&with_factory);
    }

    #[test]
    fn test_factory_hrtb_closure_feasibility() {
        // A factory may return a view that borrows the multisig. The helper
        // function pins the lifetime so closure inference stays simple.
        fn borrowed_data_view(ms: &Multisig) -> Box<dyn DataView + '_> {
            Box::new(BorrowedDataView(ms))
        }

        let ms = Builder::new(Codec::Identity)
            .with_message_bytes(&[0xCCu8; 3])
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let data = ViewBuilder::new(&ms)
            .data()
            .with_local_codec(
                Codec::Identity,
                Box::new(|ms: &Multisig| Ok(borrowed_data_view(ms))),
            )
            .build()
            .unwrap();
        assert_eq!(data.sig_bytes().unwrap(), vec![0xCCu8; 3]);
    }
}
