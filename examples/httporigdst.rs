use std::ffi::c_int;

use ngx::core::{self, ngx_make_result, NGX_RES_ERROR, NGX_RES_OK};
use ngx::ffi::{
    in_port_t, ngx_connection_local_sockaddr, ngx_http_module_t, ngx_inet_get_port, ngx_module_t,
    ngx_sock_ntop, ngx_str_t, ngx_variable_value_t, sockaddr, sockaddr_storage, INET_ADDRSTRLEN,
    NGX_HTTP_MODULE,
};
use ngx::http::{self, HttpModule, NgxVar};
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

unsafe fn ngx_get_origdst(
    request: &mut http::Request,
) -> Result<(String, in_port_t), core::Status> {
    let c = request.connection();

    if (*c).type_ != libc::SOCK_STREAM {
        ngx_log_debug_http!(request, "httporigdst: connection is not type SOCK_STREAM");
        return Err(core::Status::NGX_DECLINED);
    }

    if ngx_connection_local_sockaddr(c, std::ptr::null_mut(), 0) != core::Status::NGX_OK.into() {
        ngx_log_debug_http!(request, "httporigdst: no local sockaddr from connection");
        return Err(core::Status::NGX_ERROR);
    }

    let level: c_int;
    let optname: c_int;
    match (*(*c).local_sockaddr).sa_family as i32 {
        libc::AF_INET => {
            level = libc::SOL_IP;
            optname = libc::SO_ORIGINAL_DST;
        }
        _ => {
            ngx_log_debug_http!(request, "httporigdst: only support IPv4");
            return Err(core::Status::NGX_DECLINED);
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
        ngx_log_debug_http!(request, "httporigdst: getsockopt failed");
        return Err(core::Status::NGX_DECLINED);
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
        ngx_log_debug_http!(
            request,
            "httporigdst: ngx_sock_ntop failed to convert sockaddr"
        );
        return Err(core::Status::NGX_ERROR);
    }
    ip.truncate(e);

    let port = unsafe { ngx_inet_get_port(std::ptr::addr_of_mut!(addr) as *mut sockaddr) };

    Ok((String::from_utf8(ip).unwrap(), port))
}

fn ngx_http_orig_dst_addr_variable<'r>(
    r: &'r mut http::Request,
    v: &'r mut ngx_variable_value_t,
    _: usize,
) -> ngx::core::NgxResult {
    let ctx = r.get_module_ctx::<NgxHttpOrigDstCtx>(Module::module());
    if let Some(obj) = ctx {
        ngx_log_debug_http!(r, "httporigdst: found context and binding variable",);
        unsafe {
            obj.bind_addr(v);
        }
        return NGX_RES_OK;
    }
    // lazy initialization:
    //   get original dest information
    //   create context
    //   set context
    // bind address
    ngx_log_debug_http!(r, "httporigdst: context not found, getting address");
    let res = unsafe { ngx_get_origdst(r) };
    match res {
        Err(e) => {
            return ngx_make_result(e.0);
        }
        Ok((ip, port)) => {
            // create context,
            // set context
            let new_ctx = r
                .pool()
                .alloc_with_cleanup::<NgxHttpOrigDstCtx>(Default::default());

            if new_ctx.is_null() {
                return NGX_RES_ERROR;
            }

            ngx_log_debug_http!(r, "httporigdst: saving ip - {:?}, port - {}", ip, port,);
            unsafe {
                (*new_ctx).save(&ip, port, &r.pool());
                (*new_ctx).bind_addr(v);
            }
            r.set_module_ctx(new_ctx as _, Module::module());
        }
    }
    NGX_RES_OK
}

fn ngx_http_orig_dst_port_variable<'r>(
    r: &'r mut http::Request,
    v: &'r mut ngx_variable_value_t,
    _: usize,
) -> ngx::core::NgxResult {
    let ctx = r.get_module_ctx::<NgxHttpOrigDstCtx>(Module::module());
    if let Some(obj) = ctx {
        ngx_log_debug_http!(r, "httporigdst: found context and binding variable",);
        unsafe {
            obj.bind_port(v);
        }
        return NGX_RES_OK;
    }
    // lazy initialization:
    //   get original dest information
    //   create context
    //   set context
    // bind port
    ngx_log_debug_http!(r, "httporigdst: context not found, getting address");
    let res = unsafe { ngx_get_origdst(r) };
    match res {
        Err(e) => {
            return ngx_make_result(e.0);
        }
        Ok((ip, port)) => {
            // create context,
            // set context
            let new_ctx = r
                .pool()
                .alloc_with_cleanup::<NgxHttpOrigDstCtx>(Default::default());

            if new_ctx.is_null() {
                return NGX_RES_ERROR;
            }

            ngx_log_debug_http!(r, "httporigdst: saving ip - {:?}, port - {}", ip, port,);
            unsafe {
                (*new_ctx).save(&ip, port, &r.pool());
                (*new_ctx).bind_port(v);
            }
            r.set_module_ctx(new_ctx as _, Module::module());
        }
    }
    NGX_RES_OK
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
