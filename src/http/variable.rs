use crate::core::*;
use crate::ffi::*;
// use crate::http::status::*;
use crate::http::Request;
// use crate::http::{HttpModule, HttpModuleMainConf, NgxHttpCoreModule};

/// GF - Getter function type for NGINX variable.
pub type GF = for<'r> fn(&'r mut Request, &'r mut ngx_http_variable_value_t, usize) -> NgxResult;
/// SF - Setter function type for NGINX variable.
pub type SF = for<'r> fn(&'r mut Request, &'r ngx_http_variable_value_t, usize) -> NgxResult<()>;

/// NgxVar - structure representing an NGINX variable.
pub struct NgxVar {
    /// Name of the variable.
    pub name: &'static str,
    /// Getter function for the variable.
    pub get: Option<GF>,
    /// Setter function for the variable.
    pub set: Option<SF>,
    /// Data to be passed to getter and setter functions.
    pub data: usize,
    /// Flags for the variable.
    pub flags: u32,
}

unsafe extern "C" fn get_wrapper(
    r: *mut ngx_http_request_t,
    v: *mut ngx_http_variable_value_t,
    data: usize,
) -> ngx_int_t {
    if data != 0 {
        let r = Request::from_ngx_http_request(r);
        let v = unsafe { &mut *v };
        let var = unsafe { &*(data as *const NgxVar) };
        // SAFETY: get wrapper is used only if variable has getter
        if var.get.unwrap()(r, v, var.data).is_ok() {
            return Status::NGX_OK.into();
        }
    }
    Status::NGX_ERROR.into()
}

unsafe extern "C" fn set_wrapper(
    r: *mut ngx_http_request_t,
    v: *mut ngx_http_variable_value_t,
    data: usize,
) {
    if data != 0 {
        let r = Request::from_ngx_http_request(r);
        let v = unsafe { &*v };
        let var = unsafe { &*(data as *const NgxVar) };
        // SAFETY: set wrapper is used only if variable has setter
        let _ = var.set.unwrap()(r, v, var.data);
    }
}

impl NgxVar {
    /// Creates a new variable with default values.
    pub const fn default() -> Self {
        NgxVar {
            name: "",
            get: None,
            set: None,
            data: 0,
            flags: 0,
        }
    }

    /// Registers this variable with NGINX.
    pub fn add(&self, cf: &mut ngx_conf_t) -> bool {
        if self.name.is_empty() {
            return false;
        }

        let mut name: ngx_str_t = self.name.as_bytes().into();

        self.add_dynamic(cf, &mut name)
    }

    /// Registers this variable with NGINX using a dynamic name.
    pub fn add_dynamic(&self, cf: &mut ngx_conf_t, name: &mut ngx_str_t) -> bool {
        let var = unsafe { ngx_http_add_variable(cf, name, self.flags as ngx_uint_t) };
        if var.is_null() {
            return false;
        }
        unsafe {
            (*var).data = self as *const NgxVar as usize;
            if self.get.is_some() {
                (*var).get_handler = Some(get_wrapper);
            };
            if self.set.is_some() {
                (*var).set_handler = Some(set_wrapper);
            };
        }
        true
    }
}
