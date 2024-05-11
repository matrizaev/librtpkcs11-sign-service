#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::ffi::{c_char, CString};
use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize)]
pub struct CK_VERSION {
    pub major: u8,
    pub minor: u8,
}

impl fmt::Display for CK_VERSION {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_SLOT_INFO {
    pub slotDescription: [u8; 64usize],
    pub manufacturerID: [u8; 32usize],
    pub flags: u32,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
}

impl CK_SLOT_INFO {
    fn get_slot_description(&self) -> String {
        String::from_utf8_lossy(&self.slotDescription).to_string()
    }
    fn get_manufacturer_id(&self) -> String {
        String::from_utf8_lossy(&self.manufacturerID).to_string()
    }
}

impl fmt::Display for CK_SLOT_INFO {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "slotDescription: {},
            manufacturerID: {},
            flags: {},
            hardwareVersion: {},
            firmwareVersion: {}",
            self.get_slot_description(),
            self.get_manufacturer_id(),
            self.flags,
            self.hardwareVersion,
            self.firmwareVersion
        )
    }
}

impl Serialize for CK_SLOT_INFO {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CK_SLOT_INFO", 5)?;
        state.serialize_field("slotDescription", &self.get_slot_description())?;
        state.serialize_field("manufacturerID", &self.get_manufacturer_id())?;
        state.serialize_field("flags", &self.flags)?;
        state.serialize_field("hardwareVersion", &self.hardwareVersion)?;
        state.serialize_field("firmwareVersion", &self.firmwareVersion)?;
        state.end()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_TOKEN_INFO {
    pub label: [u8; 32usize],
    pub manufacturerID: [u8; 32usize],
    pub model: [u8; 16usize],
    pub serialNumber: [u8; 16usize],
    pub flags: u32,
    pub ulMaxSessionCount: u32,
    pub ulSessionCount: u32,
    pub ulMaxRwSessionCount: u32,
    pub ulRwSessionCount: u32,
    pub ulMaxPinLen: u32,
    pub ulMinPinLen: u32,
    pub ulTotalPublicMemory: u32,
    pub ulFreePublicMemory: u32,
    pub ulTotalPrivateMemory: u32,
    pub ulFreePrivateMemory: u32,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
    pub utcTime: [u8; 16usize],
}

impl CK_TOKEN_INFO {
    fn get_label(&self) -> String {
        String::from_utf8_lossy(&self.label).to_string()
    }
    fn get_manufacturer_id(&self) -> String {
        String::from_utf8_lossy(&self.manufacturerID).to_string()
    }
    fn get_model(&self) -> String {
        String::from_utf8_lossy(&self.model).to_string()
    }
    fn get_serial_number(&self) -> String {
        String::from_utf8_lossy(&self.serialNumber).to_string()
    }
    fn get_utc_time(&self) -> u128 {
        u128::from_be_bytes(self.utcTime)
    }
}

impl fmt::Display for CK_TOKEN_INFO {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "label: {},
            manufacturerID: {},
            model: {},
            serialNumber: {},
            flags: {},
            ulMaxSessionCount: {},
            ulSessionCount: {},
            ulMaxRwSessionCount: {},
            ulRwSessionCount: {},
            ulMaxPinLen: {},
            ulMinPinLen: {},
            ulTotalPublicMemory: {},
            ulFreePublicMemory: {},
            ulTotalPrivateMemory: {},
            ulFreePrivateMemory: {},
            hardwareVersion: {},
            firmwareVersion: {},
            utcTime: {}",
            self.get_label(),
            self.get_manufacturer_id(),
            self.get_model(),
            self.get_serial_number(),
            self.flags,
            self.ulMaxSessionCount,
            self.ulSessionCount,
            self.ulMaxRwSessionCount,
            self.ulRwSessionCount,
            self.ulMaxPinLen,
            self.ulMinPinLen,
            self.ulTotalPublicMemory,
            self.ulFreePublicMemory,
            self.ulTotalPrivateMemory,
            self.ulFreePrivateMemory,
            self.hardwareVersion,
            self.firmwareVersion,
            self.get_utc_time()
        )
    }
}

impl Serialize for CK_TOKEN_INFO {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CK_TOKEN_INFO", 18)?;
        state.serialize_field("label", &self.get_label())?;
        state.serialize_field("manufacturerID", &self.get_manufacturer_id())?;
        state.serialize_field("model", &self.get_model())?;
        state.serialize_field("serialNumber", &self.get_serial_number())?;
        state.serialize_field("flags", &self.flags)?;
        state.serialize_field("ulMaxSessionCount", &self.ulMaxSessionCount)?;
        state.serialize_field("ulSessionCount", &self.ulSessionCount)?;
        state.serialize_field("ulMaxRwSessionCount", &self.ulMaxRwSessionCount)?;
        state.serialize_field("ulRwSessionCount", &self.ulRwSessionCount)?;
        state.serialize_field("ulMaxPinLen", &self.ulMaxPinLen)?;
        state.serialize_field("ulMinPinLen", &self.ulMinPinLen)?;
        state.serialize_field("ulTotalPublicMemory", &self.ulTotalPublicMemory)?;
        state.serialize_field("ulFreePublicMemory", &self.ulFreePublicMemory)?;
        state.serialize_field("ulTotalPrivateMemory", &self.ulTotalPrivateMemory)?;
        state.serialize_field("ulFreePrivateMemory", &self.ulFreePrivateMemory)?;
        state.serialize_field("hardwareVersion", &self.hardwareVersion)?;
        state.serialize_field("firmwareVersion", &self.firmwareVersion)?;
        state.serialize_field("utcTime", &self.get_utc_time())?;
        state.end()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TByteArray {
    pub length: usize,
    pub data: *mut u8,
}

impl TByteArray {
    pub fn get_data(&self) -> Vec<u8> {
        unsafe { Vec::from_raw_parts(self.data, self.length, self.length) }
    }
}

impl Serialize for TByteArray {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TByteArray", 1)?;
        state.serialize_field("data", &self.get_data())?;
        state.end()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize)]
pub struct TSlotTokenInfo {
    pub slot_info: CK_SLOT_INFO,
    pub token_info: CK_TOKEN_INFO,
    pub valid: bool,
    pub slot_id: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TSlotTokenInfoArray {
    pub count: usize,
    pub slots_info: *mut TSlotTokenInfo,
}

impl TSlotTokenInfoArray {
    pub fn get_slots_info(&self) -> Vec<TSlotTokenInfo> {
        unsafe { Vec::from_raw_parts(self.slots_info, self.count, self.count) }
    }
}

impl Serialize for TSlotTokenInfoArray {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("TSlotTokenInfoArray", 1)?;
        state.serialize_field("slots_info", &self.get_slots_info())?;
        state.end()
    }
}

extern "C" {
    fn perform_signing(
        input: TByteArray,
        user_pin: *mut c_char,
        key_pair_id: *mut c_char,
        slot_id: usize,
    ) -> TByteArray;
}

extern "C" {
    fn get_slots_info() -> TSlotTokenInfoArray;
}

pub fn rtpkcs11sign_get_slots_info() -> Option<Vec<TSlotTokenInfo>> {
    unsafe {
        let slots_info = get_slots_info();
        if slots_info.count > 0 && !slots_info.slots_info.is_null() {
            let result = slots_info.get_slots_info();
            Some(result)
        } else {
            None
        }
    }
}

pub fn rtpkcs11sign_perform_signing(
    mut input_data: Vec<u8>,
    user_pin: &str,
    key_pair_id: &str,
    slot_id: usize,
) -> Option<Vec<u8>> {
    let user_pin = CString::new(user_pin).expect("can't create a cstring");
    let key_pair_id = CString::new(key_pair_id).expect("can't create a cstring");
    let memory_pointer: TByteArray = TByteArray {
        data: input_data.as_mut_ptr(),
        length: input_data.len(),
    };
    unsafe {
        let memory_pointer = perform_signing(
            memory_pointer,
            user_pin.into_raw(),
            key_pair_id.into_raw(),
            slot_id,
        );
        if memory_pointer.length > 0 && !memory_pointer.data.is_null() {
            let result = memory_pointer.get_data();
            Some(result)
        } else {
            None
        }
    }
}
