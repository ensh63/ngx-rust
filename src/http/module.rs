use core::error;
use core::ffi::{c_char, c_void};
use core::fmt;
use core::ptr::{self, NonNull};

use crate::core::NGX_CONF_ERROR;
use crate::core::*;
use crate::ffi::*;
use crate::http::{Request, RequestHandler};

/// MergeConfigError - configuration cannot be merged with levels above.
#[derive(Debug)]
pub enum MergeConfigError {
    /// No value provided for configuration argument
    NoValue,
}

impl error::Error for MergeConfigError {}

impl fmt::Display for MergeConfigError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MergeConfigError::NoValue => "no value".fmt(fmt),
        }
    }
}

/// The `Merge` trait provides a method for merging configuration down through each level.
///
/// A module configuration should implement this trait for setting its configuration throughout
/// each level.
pub trait Merge {
    /// Module merge function.
    ///
    /// # Returns
    /// Result, Ok on success or MergeConfigError on failure.
    fn merge(&mut self, prev: &Self) -> Result<(), MergeConfigError>;
}

impl Merge for () {
    fn merge(&mut self, _prev: &Self) -> Result<(), MergeConfigError> {
        Ok(())
    }
}

/// The `HTTPModule` trait provides the NGINX configuration stage interface.
///
/// These functions allocate structures, initialize them, and merge through the configuration
/// layers.
///
/// See <https://nginx.org/en/docs/dev/development_guide.html#adding_new_modules> for details.
pub trait HttpModule {
    /// Returns reference to a global variable of type [ngx_module_t] created for this module.
    fn module() -> &'static ngx_module_t;

    /// Returns an iterator over request handlers provided by this module.
    fn request_handlers() -> impl Iterator<Item = impl RequestHandler<Module = Self>> {
        // returns empty iterator by default
        core::iter::empty::<super::EmptyHandler<Self>>()
    }
    /// Register all request handlers provided by this module.
    ///
    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe fn register_request_handlers(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cf = unsafe { &mut *cf };
        for rh in Self::request_handlers() {
            if !rh.register(cf) {
                return Status::NGX_ERROR.into();
            }
        }
        Status::NGX_OK.into()
    }

    /// Returns an iterator over variables provided by this module.
    fn variables() -> impl Iterator<Item = &'static super::NgxVar> {
        core::iter::empty::<&'static super::NgxVar>()
    }

    /// Register all variables provided by this module.
    ///
    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe fn register_variables(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cf = unsafe { &mut *cf };
        for v in Self::variables() {
            if !v.add(cf) {
                return Status::NGX_ERROR.into();
            }
        }
        Status::NGX_OK.into()
    }

    /// Preconfiguration hook. Default implementation registers variables.
    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        Self::register_variables(cf)
    }

    /// Postconfiguration hook. Default implementation registers request handlers.
    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        Self::register_request_handlers(cf)
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn create_main_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: super::HttpModuleMainConf,
        Self::MainConf: Default,
    {
        let pool = Pool::from_ngx_pool((*cf).pool);
        pool.alloc_with_cleanup::<Self::MainConf>(Default::default()) as *mut c_void
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn init_main_conf(_cf: *mut ngx_conf_t, _conf: *mut c_void) -> *mut c_char
    where
        Self: super::HttpModuleMainConf,
        Self::MainConf: Default,
    {
        ptr::null_mut()
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn create_srv_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: super::HttpModuleServerConf,
        Self::ServerConf: Default,
    {
        let pool = Pool::from_ngx_pool((*cf).pool);
        pool.alloc_with_cleanup::<Self::ServerConf>(Default::default()) as *mut c_void
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn merge_srv_conf(
        _cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: super::HttpModuleServerConf,
        Self::ServerConf: Merge,
    {
        let prev = &mut *(prev as *mut Self::ServerConf);
        let conf = &mut *(conf as *mut Self::ServerConf);
        match conf.merge(prev) {
            Ok(_) => ptr::null_mut(),
            Err(_) => NGX_CONF_ERROR as _,
        }
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn create_loc_conf(cf: *mut ngx_conf_t) -> *mut c_void
    where
        Self: super::HttpModuleLocationConf,
        Self::LocationConf: Default,
    {
        let pool = Pool::from_ngx_pool((*cf).pool);
        pool.alloc_with_cleanup::<Self::LocationConf>(Default::default()) as *mut c_void
    }

    /// # Safety
    ///
    /// Callers should provide valid non-null `ngx_conf_t` arguments. Implementers must
    /// guard against null inputs or risk runtime errors.
    unsafe extern "C" fn merge_loc_conf(
        _cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char
    where
        Self: super::HttpModuleLocationConf,
        Self::LocationConf: Merge,
    {
        let prev = &mut *(prev as *mut Self::LocationConf);
        let conf = &mut *(conf as *mut Self::LocationConf);
        match conf.merge(prev) {
            Ok(_) => ptr::null_mut(),
            Err(_) => NGX_CONF_ERROR as _,
        }
    }
}

/// The `HttpRequestContext` trait provides methods for managing request-specific context data.
pub trait HttpRequestContext: HttpModule {
    /// The type of the context data associated with the request.
    type RequestCtx: Sized;

    /// Get module context from request.
    fn get_context(request: &mut Request) -> Option<NonNull<Self::RequestCtx>> {
        request
            .get_module_ctx_mut::<Self::RequestCtx>(Self::module())
            .map(NonNull::from)
    }

    /// Get or initialize module context in request.
    fn get_or_init_context<E: From<crate::allocator::AllocError>>(
        request: &mut Request,
        init: impl FnOnce(&mut Request, &mut Self::RequestCtx) -> Result<(), E>,
    ) -> Result<(NonNull<Self::RequestCtx>, bool), E> {
        match Self::get_context(request) {
            Some(ctx) => Ok((ctx, false)),
            None => {
                let new_ctx = request
                    .pool()
                    .allocate_with_cleanup::<Self::RequestCtx, E>(|ctx| {
                        init(request, unsafe { &mut *ctx })
                    })?;
                request.set_module_ctx(new_ctx.as_ptr() as _, Self::module());
                Ok((new_ctx, true))
            }
        }
    }

    /// Get or initialize module context in request with default value.
    fn get_or_default_context(request: &mut Request) -> NgxResult<(NonNull<Self::RequestCtx>, bool)>
    where
        Self::RequestCtx: Default,
    {
        Self::get_context(request).map_or_else(
            || {
                let new_ctx = request
                    .pool()
                    .allocate_with_cleanup::<Self::RequestCtx, NgxError>(|ctx| {
                        unsafe { ctx.write(Self::RequestCtx::default()) };
                        Ok(())
                    })?;
                request.set_module_ctx(new_ctx.as_ptr() as _, Self::module());
                Ok((new_ctx, true))
            },
            |ctx| Ok((ctx, false)),
        )
    }
}
