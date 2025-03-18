use crate::ffi::*;

/// HTTP module configuration type.
/// See <http://nginx.org/en/docs/dev/development_guide.html#http_conf>
pub enum HttpModuleConfType {
    /// Main configuration — Applies to the entire `http` block. Functions as global settings for a module.
    Main,
    /// Server configuration — Applies to a single `server` block. Functions as server-specific settings for a module.
    Server,
    /// Location configuration — Applies to a single `location`, `if` or `limit_except` block. Functions as location-specific settings for a module.
    Location,
}

/// Utility trait for the module configuration objects
/// Implement this for your type if you want to use type-safe configuration access methods.
pub trait HttpModuleConf {
    /// The module owning this configuration object
    fn module() -> &'static ngx_module_t;
}

/// Utility trait for types containing HTTP module configuration
pub trait NgxHttpConfExt {
    /// Get a configuration structure for HTTP module
    ///
    /// # Safety
    /// Caller must ensure that type `T` matches the configuration type for the specified module
    /// and context.
    unsafe fn get_http_module_conf_unchecked<T>(
        &self,
        context: HttpModuleConfType,
        module: &ngx_module_t,
    ) -> Option<&'static T>;
    /// Get a mutable reference to the configuration structure for HTTP module
    ///
    /// # Safety
    /// Caller must ensure that type `T` matches the configuration type for the specified module
    /// and context.
    unsafe fn get_http_module_conf_mut_unchecked<T>(
        &self,
        context: HttpModuleConfType,
        module: &ngx_module_t,
    ) -> Option<&'static mut T>;
}

impl NgxHttpConfExt for crate::ffi::ngx_conf_t {
    unsafe fn get_http_module_conf_unchecked<T>(
        &self,
        context: HttpModuleConfType,
        module: &ngx_module_t,
    ) -> Option<&'static T> {
        let conf_ctx = self.ctx.cast::<ngx_http_conf_ctx_t>();
        let conf_ctx = unsafe { conf_ctx.as_ref()? };

        let conf = match context {
            HttpModuleConfType::Main => conf_ctx.main_conf,
            HttpModuleConfType::Server => conf_ctx.srv_conf,
            HttpModuleConfType::Location => conf_ctx.loc_conf,
        };

        unsafe { (*conf.add(module.ctx_index)).cast::<T>().as_ref() }
    }

    unsafe fn get_http_module_conf_mut_unchecked<T>(
        &self,
        context: HttpModuleConfType,
        module: &ngx_module_t,
    ) -> Option<&'static mut T> {
        let conf_ctx = self.ctx.cast::<ngx_http_conf_ctx_t>();
        let conf_ctx = unsafe { conf_ctx.as_mut()? };

        let conf = match context {
            HttpModuleConfType::Main => conf_ctx.main_conf,
            HttpModuleConfType::Server => conf_ctx.srv_conf,
            HttpModuleConfType::Location => conf_ctx.loc_conf,
        };

        unsafe { (*conf.add(module.ctx_index)).cast::<T>().as_mut() }
    }
}

impl NgxHttpConfExt for ngx_http_upstream_srv_conf_t {
    unsafe fn get_http_module_conf_unchecked<T>(
        &self,
        context: HttpModuleConfType,
        module: &ngx_module_t,
    ) -> Option<&'static T> {
        let conf = match context {
            HttpModuleConfType::Server => self.srv_conf,
            _ => unreachable!(),
        };

        if conf.is_null() {
            return None;
        }

        unsafe { (*conf.add(module.ctx_index)).cast::<T>().as_ref() }
    }

    unsafe fn get_http_module_conf_mut_unchecked<T>(
        &self,
        context: HttpModuleConfType,
        module: &ngx_module_t,
    ) -> Option<&'static mut T> {
        let conf = match context {
            HttpModuleConfType::Server => self.srv_conf,
            _ => unreachable!(),
        };

        if conf.is_null() {
            return None;
        }

        unsafe { (*conf.add(module.ctx_index)).cast::<T>().as_mut() }
    }
}

/// Trait to define and access main module configuration
pub trait HttpModuleMainConf: HttpModuleConf {
    /// Type for main module configuration
    type MainConf;
    /// Get reference to main module configuration
    fn main_conf(o: *const impl NgxHttpConfExt) -> Option<&'static Self::MainConf> {
        unsafe {
            o.as_ref()?
                .get_http_module_conf_unchecked(HttpModuleConfType::Main, Self::module())
        }
    }
    /// Get mutable reference to main module configuration
    fn main_conf_mut(o: *const impl NgxHttpConfExt) -> Option<&'static mut Self::MainConf> {
        unsafe {
            o.as_ref()?
                .get_http_module_conf_mut_unchecked(HttpModuleConfType::Main, Self::module())
        }
    }
}

/// Trait to define and access server-specific module configuration
pub trait HttpModuleSrvConf: HttpModuleConf {
    /// Type for server-specific module configuration
    type SrvConf;
    /// Get reference to server-level module configuration
    fn srv_conf(o: *const impl NgxHttpConfExt) -> Option<&'static Self::SrvConf> {
        unsafe {
            o.as_ref()?
                .get_http_module_conf_unchecked(HttpModuleConfType::Server, Self::module())
        }
    }
    /// Get mutable reference to server-specific module configuration
    fn srv_conf_mut(o: *const impl NgxHttpConfExt) -> Option<&'static mut Self::SrvConf> {
        unsafe {
            o.as_ref()?
                .get_http_module_conf_mut_unchecked(HttpModuleConfType::Server, Self::module())
        }
    }
}

/// Trait to define and access location-specific module configuration
pub trait HttpModuleLocConf: HttpModuleConf {
    /// Type for location-specific module configuration
    type LocConf;
    /// Get reference to location-specific module configuration
    fn loc_conf(o: *const impl NgxHttpConfExt) -> Option<&'static Self::LocConf> {
        unsafe {
            o.as_ref()?
                .get_http_module_conf_unchecked(HttpModuleConfType::Location, Self::module())
        }
    }
    /// Get mutable reference to location-level module configuration
    fn loc_conf_mut(o: *const impl NgxHttpConfExt) -> Option<&'static mut Self::LocConf> {
        unsafe {
            o.as_ref()?
                .get_http_module_conf_mut_unchecked(HttpModuleConfType::Location, Self::module())
        }
    }
}

// #[macro_export]
// macro_rules! ngx_http_module_conf {
//     (@conf_type $mod_type: ty, Main $type: ty) => {
//         impl $crate::http::HttpModuleMainConf for $mod_type {
//             type MainConf = $type;
//         }
//     };
//     (@conf_type $mod_type: ty, Server $type: ty) => {
//         impl $crate::http::HttpModuleSrvConf for $mod_type {
//             type SrvConf = $type;
//         }
//     };
//     (@conf_type $mod_type: ty, Location $type: ty) => {
//         impl $crate::http::HttpModuleLocConf for $mod_type {
//             type LocConf = $type;
//         }
//     };

//     ($mod_type: ty, $module: expr, $($conf_type: tt $type: ty),+ ) => {
//         impl $crate::http::HttpModuleConf for $mod_type {
//             fn module() -> &'static $crate::ffi::ngx_module_t {
//                 #[allow(clippy::macro_metavars_in_unsafe)]
//                 unsafe {
//                     &*::core::ptr::addr_of!($module)
//                 }
//             }
//         }
//         $( ngx_http_module_conf!(@conf_type $mod_type, $conf_type $type); )+
//     };
// }

mod core {
    use crate::ffi::*;

    /// Auxiliary structure to access core module configuration
    pub struct NgxHttpCoreModule;

    impl crate::http::HttpModuleConf for NgxHttpCoreModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*::core::ptr::addr_of!(ngx_http_core_module) }
        }
    }
    impl crate::http::HttpModuleMainConf for NgxHttpCoreModule {
        type MainConf = ngx_http_core_main_conf_t;
    }
    impl crate::http::HttpModuleSrvConf for NgxHttpCoreModule {
        type SrvConf = ngx_http_core_srv_conf_t;
    }
    impl crate::http::HttpModuleLocConf for NgxHttpCoreModule {
        type LocConf = ngx_http_core_loc_conf_t;
    }
}

pub use core::*;

#[cfg(ngx_feature = "http_ssl")]
mod ssl {
    use crate::ffi::*;

    /// Auxiliary structure to access SSL module configuration
    pub struct NgxHttpSSLModule;

    impl crate::http::HttpModuleConf for NgxHttpSSLModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            #[allow(clippy::macro_metavars_in_unsafe)]
            unsafe {
                &*::core::ptr::addr_of!(ngx_http_ssl_module)
            }
        }
    }
    impl crate::http::HttpModuleSrvConf for NgxHttpSSLModule {
        type SrvConf = ngx_http_ssl_srv_conf_t;
    }
}
#[cfg(ngx_feature = "http_ssl")]
pub use ssl::*;

mod upstream {
    use crate::ffi::*;

    /// Auxiliary structure to access upstream module configuration
    pub struct NgxHttpUpstreamModule;

    impl crate::http::HttpModuleConf for NgxHttpUpstreamModule {
        fn module() -> &'static crate::ffi::ngx_module_t {
            unsafe { &*::core::ptr::addr_of!(ngx_http_upstream_module) }
        }
    }
    impl crate::http::HttpModuleMainConf for NgxHttpUpstreamModule {
        type MainConf = ngx_http_upstream_main_conf_t;
    }
    impl crate::http::HttpModuleSrvConf for NgxHttpUpstreamModule {
        type SrvConf = ngx_http_upstream_srv_conf_t;
    }
}

pub use upstream::*;

#[cfg(ngx_feature = "http_v2")]
mod http_v2 {
    use crate::ffi::*;

    /// Auxiliary structure to access HTTP V2 module configuration
    pub struct NgxHttpV2Module;

    impl crate::http::HttpModuleConf for NgxHttpV2Module {
        fn module() -> &'static crate::ffi::ngx_module_t {
            #[allow(clippy::macro_metavars_in_unsafe)]
            unsafe {
                &*::core::ptr::addr_of!(ngx_http_v2_module)
            }
        }
    }
    impl crate::http::HttpModuleSrvConf for NgxHttpV2Module {
        type SrvConf = ngx_http_v2_srv_conf_t;
    }
}

#[cfg(ngx_feature = "http_v2")]
pub use http_v2::*;

#[cfg(ngx_feature = "http_v3")]
mod http_v3 {
    use crate::ffi::*;

    /// Auxiliary structure to access HTTP V2 module configuration
    pub struct NgxHttpV3Module;

    impl crate::http::HttpModuleConf for NgxHttpV3Module {
        fn module() -> &'static crate::ffi::ngx_module_t {
            #[allow(clippy::macro_metavars_in_unsafe)]
            unsafe {
                &*::core::ptr::addr_of!(ngx_http_v3_module)
            }
        }
    }
    impl crate::http::HttpModuleSrvConf for NgxHttpV3Module {
        type SrvConf = ngx_http_v3_srv_conf_t;
    }
}

#[cfg(ngx_feature = "http_v3")]
pub use http_v3::*;
