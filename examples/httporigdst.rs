use std::ffi::c_int;
use std::ptr::NonNull;

use ngx::core::{self, NGX_RES_DECLINED, NGX_RES_ERROR, NGX_RES_OK};
use ngx::ffi::{
    in_port_t, ngx_connection_local_sockaddr, ngx_http_module_t, ngx_inet_get_port, ngx_module_t,
    ngx_sock_ntop, ngx_str_t, ngx_variable_value_t, sockaddr, sockaddr_storage, INET_ADDRSTRLEN,
    NGX_HTTP_MODULE,
};
use ngx::http::{self, HttpModule, HttpRequestContext, NgxVar};
use ngx::ngx_log_debug_http;

const IPV4_STRLEN: usize = INET_ADDRSTRLEN as usize;

#[derive(Debug, Default)]
struct NgxHttpOrigDstCtx {
    orig_dst_addr: ngx_str_t,
    orig_dst_port: ngx_str_t,
}

impl NgxHttpOrigDstCtx {
    pub fn save(&mut self, addr: &str, port: in_port_t, pool: &core::Pool) {
        self.orig_dst_addr = unsafe { ngx_str_t::from_str(pool.as_ptr(), addr) };

        let port_str = port.to_string();
        self.orig_dst_port = unsafe { ngx_str_t::from_str(pool.as_ptr(), &port_str) };
    }

    pub unsafe fn bind_addr(&self, v: &mut ngx_variable_value_t) {
        if self.orig_dst_addr.len == 0 {
            v.set_not_found(1);
            return;
        }

        v.set_valid(1);
        v.set_no_cacheable(0);
        v.set_not_found(0);
        v.set_len(self.orig_dst_addr.len as u32);
        v.data = self.orig_dst_addr.data;
    }

    pub unsafe fn bind_port(&self, v: &mut ngx_variable_value_t) {
        if self.orig_dst_port.len == 0 {
            v.set_not_found(1);
            return;
        }

        v.set_valid(1);
        v.set_no_cacheable(0);
        v.set_not_found(0);
        v.set_len(self.orig_dst_port.len as u32);
        v.data = self.orig_dst_port.data;
    }
}

static NGX_HTTP_ORIG_DST_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: None,
    merge_loc_conf: None,
};

// Generate the `ngx_modules` table with exported modules.
// This feature is required to build a 'cdylib' dynamic module outside of the NGINX buildsystem.
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_orig_dst_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_orig_dst_module: ngx_module_t = ngx_module_t {
    ctx: std::ptr::addr_of!(NGX_HTTP_ORIG_DST_MODULE_CTX) as _,
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

static NGX_HTTP_ORIG_DST_VARS: [NgxVar; 2] = [
    NgxVar {
        name: "server_orig_addr",
        get: Some(ngx_http_orig_dst_addr_variable),
        ..NgxVar::default()
    },
    NgxVar {
        name: "server_orig_port",
        get: Some(ngx_http_orig_dst_port_variable),
        ..NgxVar::default()
    },
];

#[derive(Debug)]
enum Error {
    NotSupported,
    NoAddress,
    GetSockOptFailed,
    AddrConversionFailed,
    AllocationFailed,
}

impl ::core::fmt::Display for Error {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        match self {
            Error::NotSupported => write!(f, "httporigdst: Address family not supported"),
            Error::NoAddress => write!(f, "httporigdst: No local sockaddr from connection"),
            Error::GetSockOptFailed => write!(f, "httporigdst: getsockopt failed"),
            Error::AddrConversionFailed => {
                write!(f, "httporigdst: Failed to convert sockaddr to string")
            }
            Error::AllocationFailed => write!(f, "httporigdst: Memory allocation error"),
        }
    }
}

impl From<Error> for core::NgxResult {
    fn from(value: Error) -> Self {
        match value {
            Error::NotSupported => NGX_RES_DECLINED,
            Error::NoAddress => NGX_RES_ERROR,
            Error::GetSockOptFailed => NGX_RES_DECLINED,
            Error::AddrConversionFailed => NGX_RES_ERROR,
            Error::AllocationFailed => NGX_RES_ERROR,
        }
    }
}

impl From<ngx::allocator::AllocError> for Error {
    fn from(_err: ngx::allocator::AllocError) -> Self {
        Error::AllocationFailed
    }
}

unsafe fn ngx_get_origdst(request: &mut http::Request) -> Result<(String, in_port_t), Error> {
    let c = request.connection();

    if (*c).type_ != libc::SOCK_STREAM {
        return Err(Error::NotSupported);
    }

    if ngx_connection_local_sockaddr(c, std::ptr::null_mut(), 0) != core::Status::NGX_OK.into() {
        return Err(Error::NoAddress);
    }

    let level: c_int;
    let optname: c_int;
    match (*(*c).local_sockaddr).sa_family as i32 {
        libc::AF_INET => {
            level = libc::SOL_IP;
            optname = libc::SO_ORIGINAL_DST;
        }
        _ => {
            return Err(Error::NotSupported);
        }
    }

    let mut addr: sockaddr_storage = { std::mem::zeroed() };
    let mut addrlen: libc::socklen_t = std::mem::size_of_val(&addr) as libc::socklen_t;
    let rc = libc::getsockopt(
        (*c).fd,
        level,
        optname,
        &mut addr as *mut _ as *mut _,
        &mut addrlen as *mut u32,
    );
    if rc == -1 {
        return Err(Error::GetSockOptFailed);
    }
    let mut ip: Vec<u8> = vec![0; IPV4_STRLEN];
    let e = unsafe {
        ngx_sock_ntop(
            std::ptr::addr_of_mut!(addr) as *mut sockaddr,
            std::mem::size_of::<sockaddr>() as u32,
            ip.as_mut_ptr(),
            IPV4_STRLEN,
            0,
        )
    };
    if e == 0 {
        return Err(Error::AddrConversionFailed);
    }
    ip.truncate(e);

    let port = unsafe { ngx_inet_get_port(std::ptr::addr_of_mut!(addr) as *mut sockaddr) };

    Ok((String::from_utf8(ip).unwrap(), port))
}

fn ngx_http_orig_dst_get_ctx_ref(
    r: &mut http::Request,
) -> Result<NonNull<NgxHttpOrigDstCtx>, Error> {
    Module::get_or_init_context::<Error>(r, |r, ctx| {
        unsafe { ngx_get_origdst(r) }
            .inspect_err(|e| {
                ngx_log_debug_http!(r, "{e}");
            })
            .map(|(ip, port)| {
                ngx_log_debug_http!(r, "httporigdst: saving ip - {:?}, port - {}", ip, port,);
                ctx.save(&ip, port, &r.pool());
            })
    })
    .map(|(ctx, _)| ctx)
}

fn ngx_http_orig_dst_addr_variable<'r>(
    r: &'r mut http::Request,
    v: &'r mut ngx_variable_value_t,
    _: usize,
) -> ngx::core::NgxResult {
    match ngx_http_orig_dst_get_ctx_ref(r) {
        Err(e) => e.into(),
        Ok(ctx) => {
            unsafe { ctx.as_ref().bind_addr(v) };
            NGX_RES_OK
        }
    }
}

fn ngx_http_orig_dst_port_variable<'r>(
    r: &'r mut http::Request,
    v: &'r mut ngx_variable_value_t,
    _: usize,
) -> ngx::core::NgxResult {
    match ngx_http_orig_dst_get_ctx_ref(r) {
        Err(e) => e.into(),
        Ok(ctx) => {
            unsafe { ctx.as_ref().bind_port(v) };
            NGX_RES_OK
        }
    }
}

struct Module;

impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_orig_dst_module) }
    }

    fn variables() -> impl Iterator<Item = &'static http::NgxVar> {
        NGX_HTTP_ORIG_DST_VARS.iter()
    }
}

impl HttpRequestContext for Module {
    type RequestCtx = NgxHttpOrigDstCtx;
}
