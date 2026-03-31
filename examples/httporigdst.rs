use core::ffi::c_int;
use core::mem;
use core::ptr::{self, NonNull};

use ngx::core::Status;
use ngx::ffi::{
    INET_ADDRSTRLEN, NGX_HTTP_MODULE, in_port_t, ngx_conf_t, ngx_connection_local_sockaddr,
    ngx_http_add_variable, ngx_http_module_t, ngx_http_variable_t, ngx_inet_get_port, ngx_int_t,
    ngx_module_t, ngx_sock_ntop, ngx_str_t, ngx_variable_value_t, sockaddr, sockaddr_storage,
};
use ngx::http::{self, HttpModule, Request, RequestContext};
use ngx::{http_variable_get, ngx_log_debug_http, ngx_string};

const IPV4_STRLEN: usize = INET_ADDRSTRLEN as usize;

#[derive(Debug, Default)]
struct NgxHttpOrigDstCtx {
    orig_dst_addr: ngx_str_t,
    orig_dst_port: ngx_str_t,
}

impl NgxHttpOrigDstCtx {
    pub fn save(&mut self, addr: &str, port: in_port_t, r: &Request) -> Result<(), Status> {
        ngx_log_debug_http!(r, "httporigdst: saving ip - {addr}, port - {port}");
        let pool = r.pool();
        self.orig_dst_addr = unsafe {
            ngx_str_t::from_bytes(pool.as_ptr(), addr.as_bytes()).ok_or(Status::NGX_ERROR)?
        };

        let port_str = port.to_string();
        self.orig_dst_port = unsafe {
            ngx_str_t::from_bytes(pool.as_ptr(), port_str.as_bytes()).ok_or(Status::NGX_ERROR)?
        };
        Ok(())
    }

    pub unsafe fn bind_addr(&self, v: *mut ngx_variable_value_t) {
        let mut v = NonNull::new(v).unwrap();
        let v = unsafe { v.as_mut() };
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

    pub unsafe fn bind_port(&self, v: *mut ngx_variable_value_t) {
        let mut v = NonNull::new(v).unwrap();
        let v = unsafe { v.as_mut() };
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
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_orig_dst_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_ORIG_DST_MODULE_CTX as _,
    commands: ptr::null_mut(),
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

static mut NGX_HTTP_ORIG_DST_VARS: [ngx_http_variable_t; 2] = [
    // ngx_str_t name
    // ngx_http_set_variable_pt set_handler
    // ngx_http_get_variable_pt get_handler
    // uintptr_t data
    // ngx_uint_t flags
    // ngx_uint_t index
    ngx_http_variable_t {
        name: ngx_string!("server_orig_addr"),
        set_handler: None,
        get_handler: Some(ngx_http_orig_dst_addr_variable),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_variable_t {
        name: ngx_string!("server_orig_port"),
        set_handler: None,
        get_handler: Some(ngx_http_orig_dst_port_variable),
        data: 0,
        flags: 0,
        index: 0,
    },
];

unsafe fn ngx_get_origdst(request: &http::Request) -> Result<(String, in_port_t), Status> {
    let c = request.connection();

    if unsafe { (*c).type_ } != libc::SOCK_STREAM {
        ngx_log_debug_http!(request, "httporigdst: connection is not type SOCK_STREAM");
        return Err(Status::NGX_DECLINED);
    }

    if unsafe { ngx_connection_local_sockaddr(c, ptr::null_mut(), 0) } != Status::NGX_OK.into() {
        ngx_log_debug_http!(request, "httporigdst: no local sockaddr from connection");
        return Err(Status::NGX_ERROR);
    }

    let level: c_int;
    let optname: c_int;
    match unsafe { (*(*c).local_sockaddr).sa_family } as i32 {
        libc::AF_INET => {
            level = libc::SOL_IP;
            optname = libc::SO_ORIGINAL_DST;
        }
        _ => {
            ngx_log_debug_http!(request, "httporigdst: only support IPv4");
            return Err(Status::NGX_DECLINED);
        }
    }

    let mut addr: sockaddr_storage = unsafe { mem::zeroed() };
    let mut addrlen: libc::socklen_t = mem::size_of_val(&addr) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            (*c).fd,
            level,
            optname,
            (&raw mut addr).cast(),
            &raw mut addrlen,
        )
    };
    if rc == -1 {
        ngx_log_debug_http!(request, "httporigdst: getsockopt failed");
        return Err(Status::NGX_DECLINED);
    }
    let mut ip: Vec<u8> = vec![0; IPV4_STRLEN];
    let e = unsafe {
        ngx_sock_ntop(
            (&raw mut addr).cast(),
            mem::size_of::<sockaddr>() as u32,
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
        return Err(Status::NGX_ERROR);
    }
    ip.truncate(e);

    let port = unsafe { ngx_inet_get_port((&raw mut addr).cast()) };

    Ok((String::from_utf8(ip).unwrap(), port))
}

type RCtx = RequestContext<Module, NgxHttpOrigDstCtx>;

http_variable_get!(
    ngx_http_orig_dst_addr_variable,
    |request: &mut http::Request, v: *mut ngx_variable_value_t, _: usize| {
        match RCtx::get(request) {
            Some(ctx) => {
                ngx_log_debug_http!(request, "httporigdst: found context and binding variable");
                Ok(ctx)
            }
            None => {
                ngx_log_debug_http!(request, "httporigdst: context not found, getting address");
                unsafe { ngx_get_origdst(request) }.map_or_else(Err, |(ip, port)| {
                    RCtx::try_set(request, |request| {
                        let mut ctx = NgxHttpOrigDstCtx::default();
                        ctx.save(&ip, port, request).map(|_| ctx)
                    })
                    .map(|ctx| ctx as &NgxHttpOrigDstCtx)
                })
            }
        }
        .inspect(|ctx| unsafe { ctx.bind_addr(v) })
        .into()
    }
);

http_variable_get!(
    ngx_http_orig_dst_port_variable,
    |request: &mut http::Request, v: *mut ngx_variable_value_t, _: usize| {
        match RCtx::get(request) {
            Some(ctx) => {
                ngx_log_debug_http!(request, "httporigdst: found context and binding variable");
                Ok(ctx)
            }
            None => {
                ngx_log_debug_http!(request, "httporigdst: context not found, getting address");
                unsafe { ngx_get_origdst(request) }.map_or_else(Err, |(ip, port)| {
                    RCtx::try_set(request, |request| {
                        let mut ctx = NgxHttpOrigDstCtx::default();
                        ctx.save(&ip, port, request).map(|_| ctx)
                    })
                    .map(|ctx| ctx as &NgxHttpOrigDstCtx)
                })
            }
        }
        .inspect(|ctx| unsafe { ctx.bind_port(v) })
        .into()
    }
);

struct Module;

impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_orig_dst_module) }
    }

    // static ngx_int_t ngx_http_orig_dst_add_variables(ngx_conf_t *cf)
    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        for mut v in unsafe { NGX_HTTP_ORIG_DST_VARS } {
            let var = NonNull::new(unsafe { ngx_http_add_variable(cf, &raw mut v.name, v.flags) });
            if var.is_none() {
                return Status::NGX_ERROR.into();
            }
            let mut var = var.unwrap();
            let var = unsafe { var.as_mut() };
            var.get_handler = v.get_handler;
            var.data = v.data;
        }
        Status::NGX_OK.into()
    }
}
