// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Mechanisms of NIST key-based key derive functions (SP 800-108, informally KBKDF)
//! See: <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061446>

use std::{convert::TryInto, marker::PhantomData, ptr};

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_DERIVED_KEY, CK_DERIVED_KEY_PTR, CK_OBJECT_HANDLE,
    CK_PRF_DATA_PARAM, CK_PRF_DATA_PARAM_PTR, CK_SP800_108_BYTE_ARRAY, CK_SP800_108_COUNTER,
    CK_SP800_108_COUNTER_FORMAT, CK_SP800_108_DKM_LENGTH, CK_SP800_108_DKM_LENGTH_FORMAT,
    CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS,
    CK_SP800_108_ITERATION_VARIABLE, CK_ULONG,
};

use crate::object::Attribute;

use super::MechanismType;

// TODO: should this go somewhere else, since it's so general?
/// Endianness of byte representation of data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Endianness {
    /// Little endian.
    Little,
    /// Big endian.
    Big,
}

/// Defines encoding format for a counter value.
///
/// Corresponds to CK_SP800_108_COUNTER_FORMAT.
#[derive(Debug, Clone, Copy)]
pub struct KbkdfCounterFormat {
    endianness: Endianness,
    width_in_bits: usize,
}

impl From<KbkdfCounterFormat> for CK_SP800_108_COUNTER_FORMAT {
    fn from(value: KbkdfCounterFormat) -> Self {
        Self {
            bLittleEndian: (value.endianness == Endianness::Little).into(),
            ulWidthInBits: value
                .width_in_bits
                .try_into()
                .expect("bit width of KBKDF internal counter does not fit in CK_ULONG"),
        }
    }
}

/// Method for calculating length of DKM (derived key material).
///
/// Corresponds to CK_SP800_108_DKM_LENGTH_METHOD.
#[derive(Debug, Clone, Copy)]
pub enum DkmLengthMethod {
    /// Sum of length of all keys derived by given invocation of KDF.
    SumOfKeys,
    /// Sum of length of all segments of output produced by PRF in given invocation of KDF.
    SumOfSegments,
}

/// Defines encoding format for DKM (derived key material).
///
/// Corresponds to CK_SP800_108_DKM_LENGTH_FORMAT.
#[derive(Debug, Clone, Copy)]
pub struct KbkdfDkmLengthFormat {
    dkm_length_method: DkmLengthMethod,
    endianness: Endianness,
    width_in_bits: usize,
}

impl From<KbkdfDkmLengthFormat> for CK_SP800_108_DKM_LENGTH_FORMAT {
    fn from(value: KbkdfDkmLengthFormat) -> Self {
        Self {
            dkmLengthMethod: match value.dkm_length_method {
                DkmLengthMethod::SumOfKeys => CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS,
                DkmLengthMethod::SumOfSegments => CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS,
            },
            bLittleEndian: (value.endianness == Endianness::Little).into(),
            ulWidthInBits: value
                .width_in_bits
                .try_into()
                .expect("bit width of KBKDF derived key material does not fit in CK_ULONG"),
        }
    }
}

// TODO: is it wrong to be using the CK_... structs directly?
/// A segment of input data for the PRF.
///
/// Corresponds to CK_PRF_DATA_PARAM.
// #[derive(Debug, Clone, Copy)]
// pub enum PrfDataParam<'a> {
//     ///
//     IterationVariable(Option<KbkdfCounterFormat>),
//     ///
//     Counter(KbkdfCounterFormat),
//     ///
//     DkmLength(KbkdfDkmLengthFormat),
//     ///
//     ByteArray(&'a [u8]),
// }

// TODO: This way enforces semantics about certain arguments (i.e. must have an iteration variable, can have one or no dkm length, and an unlimited amount of byte arrays)
// TODO: Figure out if PKCS#11 backend enforces this (i.e. if it returns an error if you provide no iteration variable or 2 dkm lengths). If it does, choose the other option, which is nicer to work with
// #[derive(Debug, Clone, Copy)]
// pub struct PrfCounterDataParam<'a> {
//     ///
//     iteration_variable: KbkdfCounterFormat,
//     ///
//     dkm_length: Option<KbkdfDkmLengthFormat>,
//     ///
//     byte_arrays: Vec<&'a [u8]>,
// }

// #[derive(Debug, Clone, Copy)]
// pub struct PrfFeedbackDataParam<'a> {
//     ///
//     iteration_variable: (),
//     counter: Option<KbkdfCounterFormat>,
//     ///
//     dkm_length: Option<KbkdfDkmLengthFormat>,
//     ///
//     byte_arrays: Vec<&'a [u8]>,
// }

// #[derive(Debug, Clone, Copy)]
// pub struct PrfDoublePipelineDataParam<'a> {
//     ///
//     iteration_variable: (),
//     counter: Option<KbkdfCounterFormat>,
//     ///
//     dkm_length: Option<KbkdfDkmLengthFormat>,
//     ///
//     byte_arrays: Vec<&'a [u8]>,
// }

/// A segment of input data for the PRF, to be used to construct a sequence of input.
///
/// Corresponds to CK_PRF_DATA_PARAM in the specific cases of the KDF operating in feedback- or double pipeline-mode.
#[derive(Debug, Clone, Copy)]
pub enum PrfDataParam<'a> {
    /// Identifies location of predefined iteration variable in constructed PRF input data.
    IterationVariable,
    /// Identifies location of counter in constructed PRF input data.
    Counter(KbkdfCounterFormat),
    /// Identifies location of DKM (derived key material) length in constructed PRF input data.
    DkmLength(KbkdfDkmLengthFormat),
    /// Identifies location and value of byte array of data in constructed PRF input data.
    ByteArray(&'a [u8]),
}

/// A segment of input data for the PRF, to be used to construct a sequence of input.
///
/// Corresponds to CK_PRF_DATA_PARAM in the specific case of the KDF operating in counter-mode.
#[derive(Debug, Clone, Copy)]
pub enum PrfCounterDataParam<'a> {
    /// Identifies location of iteration variable (a counter in this case) in constructed PRF input data.
    IterationVariable(KbkdfCounterFormat),
    /// Identifies location of DKM (derived key material) length in constructed PRF input data.
    DkmLength(KbkdfDkmLengthFormat),
    /// Identifies location and value of byte array of data in constructed PRF input data.
    ByteArray(&'a [u8]),
}

/// Parameters for additional key to be derived from base key.
#[derive(Debug, Clone, Copy)]
pub struct DerivedKey<'a> {
    template: &'a [Attribute],
    object_handle: CK_OBJECT_HANDLE,
}

impl<'a> DerivedKey<'a> {
    /// Construct template for additional key to be derived by KDF.
    ///
    /// # Arguments
    ///
    /// * `template` - The template for the key to be derived.
    pub fn new(template: &'a [Attribute]) -> Self {
        Self {
            template,
            object_handle: 0,
        }
    }
}

/// NIST SP 800-108 (aka KBKDF) counter-mode parameters.
///
/// This structure wraps a `CK_SP800_108_KDF_PARAMS` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
// pub struct KbkdfParams<'a> {
pub struct KbkdfCounterParams<'a> {
    inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

// impl<'a> KbkdfParams<'a> {
impl<'a> KbkdfCounterParams<'a> {
    /// Construct parameters for NIST SP 800-108 KDF (aka KBKDF) pseuderandom function-based key
    /// derivation function, in counter-mode.
    ///
    /// # Arguments
    ///
    /// * `prf_mechanism` - The pseudorandom function that underlies the KBKDF operation.
    ///
    /// * `prf_data_params` - The sequence of data segments used as input data for the PRF. Requires at least [`PrfCounterDataParam::IterationVariable`].
    ///
    /// * `additional_derived_keys` - Any additional keys to be generated by the KDF from the base key.
    pub fn new(
        prf_mechanism: MechanismType,
        prf_data_params: Vec<PrfDataParam<'a>>, // TODO: should this be &'a [PrfDataParam<'a>]? Do we need to have pointers to the original data in the output Vec<CK_PRF_DATA_PARAM>?
        mut additional_derived_keys: Vec<DerivedKey<'a>>, // TODO: should this be &'a [DerivedKey<'a>]? Do we need to have pointers to the original data in the output Vec<CK_DERIVED_KEY>?
    ) -> Self {
        let prf_data_params: Vec<CK_PRF_DATA_PARAM> = prf_data_params
            .iter()
            // .map(encode_data_param(prf_mechanism))
            .map(Into::into)
            .collect(); // TODO: same comment as about about iter() vs into_iter()
        let additional_derived_keys: Vec<CK_DERIVED_KEY> = additional_derived_keys
            .iter_mut()
            // .map(encode_derived_key)
            .map(Into::into)
            .collect(); // TODO: same comment as about about iter() vs into_iter()

        Self {
            inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS {
                prfType: prf_mechanism.into(),
                ulNumberOfDataParams: prf_data_params
                    .len()
                    .try_into()
                    .expect("number of data parameters does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
                pDataParams: prf_data_params.as_ptr() as CK_PRF_DATA_PARAM_PTR,
                ulAdditionalDerivedKeys: additional_derived_keys
                    .len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
                pAdditionalDerivedKeys: additional_derived_keys.as_ptr() as CK_DERIVED_KEY_PTR, // TODO: is this actually as_mut_ptr() because we're modifying the handles contained within?
            },
            _marker: PhantomData,
        }
    }

    // TODO: are there any more methods I need to implement, as in the HKDF case?
}

/// NIST SP 800-108 (aka KBKDF) feedback-mode parameters.
///
/// This structure wraps a `CK_SP800_108_FEEDBACK_KDF_PARAMS` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KbkdfFeedbackParams<'a> {
    inner: cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> KbkdfFeedbackParams<'a> {
    /// Construct parameters for NIST SP 800-108 KDF (aka KBKDF) pseuderandom function-based key
    /// derivation function, in feedback-mode.
    ///
    /// # Arguments
    ///
    /// * `prf_mechanism` - The pseudorandom function that underlies the KBKDF operation.
    ///
    /// * `prf_data_params` - The sequence of data segments used as input data for the PRF. Requires at least [`PrfCounterDataParam::IterationVariable`].
    ///
    /// * `iv` - The IV to be used for the feedback-mode KDF.
    ///
    /// * `additional_derived_keys` - Any additional keys to be generated by the KDF from the base key.
    pub fn new(
        prf_mechanism: MechanismType,
        prf_data_params: Vec<PrfDataParam<'a>>, // TODO: should this be &'a [PrfDataParam<'a>]? Do we need to have pointers to the original data in the output Vec<CK_PRF_DATA_PARAM>?
        iv: Option<&'a [u8]>, // TODO: should this be &'a [u8]? Do we need to have pointers to the original data in the output?
        mut additional_derived_keys: Vec<DerivedKey<'a>>, // TODO: should this be &'a [DerivedKey<'a>]? Do we need to have pointers to the original data in the output Vec<CK_DERIVED_KEY>?
    ) -> Self {
        let prf_data_params: Vec<CK_PRF_DATA_PARAM> = prf_data_params
            .iter()
            // .map(encode_data_param(prf_mechanism))
            .map(Into::into)
            .collect(); // TODO: same comment as about about iter() vs into_iter()
        let additional_derived_keys: Vec<CK_DERIVED_KEY> = additional_derived_keys
            .iter_mut()
            // .map(encode_derived_key)
            .map(Into::into)
            .collect(); // TODO: same comment as about about iter() vs into_iter()

        Self {
            inner: cryptoki_sys::CK_SP800_108_FEEDBACK_KDF_PARAMS {
                prfType: prf_mechanism.into(),
                ulNumberOfDataParams: prf_data_params
                    .len()
                    .try_into()
                    .expect("number of data parameters does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
                pDataParams: prf_data_params.as_ptr() as CK_PRF_DATA_PARAM_PTR,
                ulIVLen: iv.map_or(0, |iv| {
                    iv.len()
                        .try_into()
                        .expect("IV length does not fit in CK_ULONG")
                }),
                pIV: iv.map_or(ptr::null_mut(), |iv| iv.as_ptr() as *mut _),
                ulAdditionalDerivedKeys: additional_derived_keys
                    .len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
                pAdditionalDerivedKeys: additional_derived_keys.as_ptr() as CK_DERIVED_KEY_PTR, // TODO: is this actually as_mut_ptr() because we're modifying the handles contained within?
            },
            _marker: PhantomData,
        }
    }
}

/// NIST SP 800-108 (aka KBKDF) double pipeline-mode parameters.
///
/// This structure wraps a `CK_SP800_108_KDF_PARAMS` structure.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct KbkdfDoublePipelineParams<'a> {
    inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS,
    /// Marker type to ensure we don't outlive the data
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> KbkdfDoublePipelineParams<'a> {
    /// Construct parameters for NIST SP 800-108 KDF (aka KBKDF) pseuderandom function-based key
    /// derivation function, in double pipeline-mode.
    ///
    /// # Arguments
    ///
    /// * `prf_mechanism` - The pseudorandom function that underlies the KBKDF operation.
    ///
    /// * `prf_data_params` - The sequence of data segments used as input data for the PRF. Requires at least [`PrfCounterDataParam::IterationVariable`].
    ///
    /// * `additional_derived_keys` - Any additional keys to be generated by the KDF from the base key.
    pub fn new(
        prf_mechanism: MechanismType,
        prf_data_params: Vec<PrfDataParam<'a>>, // TODO: should this be &'a [PrfDataParam<'a>]? Do we need to have pointers to the original data in the output Vec<CK_PRF_DATA_PARAM>?
        mut additional_derived_keys: Vec<DerivedKey<'a>>, // TODO: should this be &'a [DerivedKey<'a>]? Do we need to have pointers to the original data in the output Vec<CK_DERIVED_KEY>?
    ) -> Self {
        let prf_data_params: Vec<CK_PRF_DATA_PARAM> = prf_data_params
            .iter()
            // .map(encode_data_param(prf_mechanism))
            .map(Into::into)
            .collect(); // TODO: same comment as about about iter() vs into_iter()
        let additional_derived_keys: Vec<CK_DERIVED_KEY> = additional_derived_keys
            .iter_mut()
            // .map(encode_derived_key)
            .map(Into::into)
            .collect(); // TODO: same comment as about about iter() vs into_iter()

        Self {
            inner: cryptoki_sys::CK_SP800_108_KDF_PARAMS {
                prfType: prf_mechanism.into(),
                ulNumberOfDataParams: prf_data_params
                    .len()
                    .try_into()
                    .expect("number of data parameters does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
                pDataParams: prf_data_params.as_ptr() as CK_PRF_DATA_PARAM_PTR,
                ulAdditionalDerivedKeys: additional_derived_keys
                    .len()
                    .try_into()
                    .expect("number of additional derived keys does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
                pAdditionalDerivedKeys: additional_derived_keys.as_ptr() as CK_DERIVED_KEY_PTR, // TODO: is this actually as_mut_ptr() because we're modifying the handles contained within?
            },
            _marker: PhantomData,
        }
    }

    // TODO: are there any more methods I need to implement, as in the HKDF case?
}

// TODO: we can only use this if the PCKS#11 backend handles the case of counter mode => IterationVariable
// impl<'a> From<PrfDataParam<'a>> for CK_PRF_DATA_PARAM {
//     fn from(value: PrfDataParam<'a>) -> Self {
//         Self {
//             type_: match value {
//                 PrfDataParam::IterationVariable(_) => CK_SP800_108_ITERATION_VARIABLE,
//                 PrfDataParam::Counter(_) => CK_SP800_108_COUNTER,
//                 PrfDataParam::DkmLength(_) => CK_SP800_108_DKM_LENGTH,
//                 PrfDataParam::ByteArray(_) => CK_SP800_108_BYTE_ARRAY,
//             },
//             pValue: match value {
//                 PrfDataParam::IterationVariable(None) => ptr::null_mut(),
//                 PrfDataParam::IterationVariable(Some(inner)) | PrfDataParam::Counter(inner) => {
//                     &inner as *const _ as *mut _
//                 }
//                 PrfDataParam::DkmLength(inner) => &inner as *const _ as *mut _,
//                 PrfDataParam::ByteArray(data) => data.as_ptr() as *mut _,
//             },
//             ulValueLen: match value {
//                 PrfDataParam::IterationVariable(None) => 0,
//                 PrfDataParam::IterationVariable(Some(_)) | PrfDataParam::Counter(_) => {
//                     size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG
//                 }
//                 PrfDataParam::DkmLength(_) => {
//                     size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG
//                 }
//                 PrfDataParam::ByteArray(data) => data
//                     .len()
//                     .try_into()
//                     .expect("length of data parameter does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
//             },
//         }
//     }
// }

// TODO: we can only use this if the PCKS#11 backend handles the case of counter mode => IterationVariable
impl<'a> From<&PrfDataParam<'a>> for CK_PRF_DATA_PARAM {
    fn from(value: &PrfDataParam<'a>) -> Self {
        Self {
            type_: match value {
                PrfDataParam::IterationVariable => CK_SP800_108_ITERATION_VARIABLE,
                PrfDataParam::Counter(_) => CK_SP800_108_COUNTER,
                PrfDataParam::DkmLength(_) => CK_SP800_108_DKM_LENGTH,
                PrfDataParam::ByteArray(_) => CK_SP800_108_BYTE_ARRAY,
            },
            pValue: match value {
                PrfDataParam::IterationVariable => ptr::null_mut(),
                PrfDataParam::Counter(inner) => inner as *const _ as *mut _,
                PrfDataParam::DkmLength(inner) => inner as *const _ as *mut _,
                PrfDataParam::ByteArray(data) => data.as_ptr() as *mut _, // TODO: be careful of && here, how does it behave?
            },
            ulValueLen: match value {
                PrfDataParam::IterationVariable => 0,
                PrfDataParam::Counter(_) => size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG,
                PrfDataParam::DkmLength(_) => {
                    size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG
                }
                PrfDataParam::ByteArray(data) => {
                    data // TODO: be careful of && here, how does it behave?
                        .len()
                        .try_into()
                        .expect("length of data parameter does not fit in CK_ULONG")
                } // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
            },
        }
    }
}

// TODO: we can only use this if the PCKS#11 backend handles the case of counter mode => IterationVariable
impl<'a> From<&PrfCounterDataParam<'a>> for CK_PRF_DATA_PARAM {
    fn from(value: &PrfCounterDataParam<'a>) -> Self {
        Self {
            type_: match value {
                PrfCounterDataParam::IterationVariable(_) => CK_SP800_108_ITERATION_VARIABLE,
                PrfCounterDataParam::DkmLength(_) => CK_SP800_108_DKM_LENGTH,
                PrfCounterDataParam::ByteArray(_) => CK_SP800_108_BYTE_ARRAY,
            },
            pValue: match value {
                PrfCounterDataParam::IterationVariable(inner) => inner as *const _ as *mut _,
                PrfCounterDataParam::DkmLength(inner) => inner as *const _ as *mut _,
                PrfCounterDataParam::ByteArray(data) => data.as_ptr() as *mut _, // TODO: be careful of && here, how does it behave?
            },
            ulValueLen: match value {
                PrfCounterDataParam::IterationVariable(_) => {
                    size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG
                }
                PrfCounterDataParam::DkmLength(_) => {
                    size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG
                }
                PrfCounterDataParam::ByteArray(data) => {
                    data // TODO: be careful of && here, how does it behave?
                        .len()
                        .try_into()
                        .expect("length of data parameter does not fit in CK_ULONG")
                } // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
            },
        }
    }
}

// fn encode_data_param<'a>(
//     prf_mechanism: MechanismType,
// ) -> impl Fn(PrfDataParam<'a>) -> CK_PRF_DATA_PARAM {
//     move |data_param| {
//         match data_param {
//             PrfDataParam::IterationVariable(Some(_))
//                 if prf_mechanism != MechanismType::SP800_108_COUNTER_KDF =>
//             {
//                 panic!("SP 800-108 KDF does not allow an iteration variable data parameter in any mode except counter mode")
//                 // TODO: does the PKCS#11 backend handle this?
//             }
//             PrfDataParam::IterationVariable(None)
//                 if prf_mechanism == MechanismType::SP800_108_COUNTER_KDF =>
//             {
//                 panic!("SP 800-108 KDF in counter mode must have an iteration variable set, if one is provided as a data parameter")
//                 // TODO: does the PKCS#11 backend handle this?
//             }
//             PrfDataParam::IterationVariable(Some(counter_format)) => {
//                 let counter_format: CK_SP800_108_COUNTER_FORMAT = counter_format.into();

//                 CK_PRF_DATA_PARAM {
//                     type_: CK_SP800_108_ITERATION_VARIABLE,
//                     pValue: &counter_format as *const _ as *mut _,
//                     ulValueLen: size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG,
//                 }
//             }
//             PrfDataParam::IterationVariable(None) => CK_PRF_DATA_PARAM {
//                 type_: CK_SP800_108_ITERATION_VARIABLE,
//                 pValue: ptr::null_mut(),
//                 ulValueLen: 0,
//             },
//             PrfDataParam::Counter(counter_format) => {
//                 let counter_format: CK_SP800_108_COUNTER_FORMAT = counter_format.into();

//                 CK_PRF_DATA_PARAM {
//                     type_: CK_SP800_108_COUNTER,
//                     pValue: &counter_format as *const _ as *mut _,
//                     ulValueLen: size_of::<CK_SP800_108_COUNTER_FORMAT>() as CK_ULONG,
//                 }
//             }
//             PrfDataParam::DkmLength(dkm_length_format) => {
//                 let dkm_length_format: CK_SP800_108_DKM_LENGTH_FORMAT = dkm_length_format.into();

//                 CK_PRF_DATA_PARAM {
//                     type_: CK_SP800_108_DKM_LENGTH,
//                     pValue: &dkm_length_format as *const _ as *mut _,
//                     ulValueLen: size_of::<CK_SP800_108_DKM_LENGTH_FORMAT>() as CK_ULONG,
//                 }
//             }
//             PrfDataParam::ByteArray(data) => CK_PRF_DATA_PARAM {
//                 type_: CK_SP800_108_BYTE_ARRAY,
//                 pValue: data.as_ptr() as *mut _,
//                 ulValueLen: data
//                     .len()
//                     .try_into()
//                     .expect("length of data parameter does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
//             },
//         }
//     }
// }

impl<'a> From<&mut DerivedKey<'a>> for CK_DERIVED_KEY {
    fn from(value: &mut DerivedKey<'a>) -> Self {
        let template: Vec<CK_ATTRIBUTE> = value.template.iter().map(Into::into).collect();

        Self {
            pTemplate: template.as_ptr() as CK_ATTRIBUTE_PTR,
            ulAttributeCount: template
                .len()
                .try_into()
                .expect("number of attributes in template does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
            phKey: &mut value.object_handle,
        }
    }
}

// fn encode_derived_key<'a>(mut derived_key: DerivedKey<'a>) -> CK_DERIVED_KEY {
//     let template: Vec<CK_ATTRIBUTE> = derived_key
//         .template
//         .iter()
//         .map(Into::into())
//         .collect();

//     CK_DERIVED_KEY {
//         pTemplate: template.as_ptr() as CK_ATTRIBUTE_PTR,
//         ulAttributeCount: template
//             .len()
//             .try_into()
//             .expect("number of attributes in template does not fit in CK_ULONG"), // TODO: expect() as in hkdf.rs? Or ? as in key_management.rs?
//         phKey: derived_key.object_handle.handle_ptr(), // TODO: what if we just returned a new ObjectHandle? Instead of trying to overwrite the handle to an existing one? Do even overwrite the handle itself? Or just the content on the HSM that the handle points to?
//     }
// }
