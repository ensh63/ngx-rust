use ngx::http::{
    add_phase_handler, AsyncHandler, AsyncSubRequestBuilder, HttpModule, HttpPhase, Request,
};
use ngx::{async_ as ngx_async, ngx_log_debug_http, ngx_log_error};

use nginx_sys::ngx_int_t;

struct SampleAsyncHandler;

impl AsyncHandler for SampleAsyncHandler {
    const PHASE: HttpPhase = HttpPhase::Access;
    type Module = Module;
    type ReturnType = ngx_int_t;

    fn worker(request: &mut Request) -> impl core::future::Future<Output = ngx_int_t> {
        ngx_log_debug_http!(request, "worker started");

        let log = request.log();

        let sub = AsyncSubRequestBuilder::new("/proxy")
            //.args("arg1=val1&arg2=val2")
            .in_memory()
            .waited()
            .build(request);

        async move {
            if sub.is_none() {
                return nginx_sys::NGX_ERROR as _;
            }

            let fut = sub.unwrap();

            let subrc = fut.await;

            ngx_log_error!(nginx_sys::NGX_LOG_INFO, log, "Subrequest rc {}", subrc.0);

            if subrc.0 != nginx_sys::NGX_OK as _ || subrc.1.is_none() {
                return nginx_sys::NGX_ERROR as _;
            }

            let sr = subrc.1.unwrap();

            ngx_log_error!(
                nginx_sys::NGX_LOG_INFO,
                log,
                "Subrequest status: {:?}",
                sr.get_status()
            );

            ngx_async::sleep(core::time::Duration::from_secs(2)).await;

            let mut resp_len: usize = 0;
            if let Some(out) = sr.get_out() {
                if !out.buf.is_null() {
                    let b = unsafe { &*out.buf };
                    resp_len = unsafe { b.last.offset_from(b.pos) } as usize;
                }
            }
            ngx_log_error!(
                nginx_sys::NGX_LOG_INFO,
                log,
                "Async handler after timeout; subrequest response length: {}",
                resp_len
            );

            nginx_sys::NGX_OK as _
        }
    }
}

static NGX_HTTP_ASYNC_REQUEST_MODULE_CTX: nginx_sys::ngx_http_module_t =
    nginx_sys::ngx_http_module_t {
        preconfiguration: None,
        postconfiguration: Some(Module::postconfiguration),
        create_main_conf: None,
        init_main_conf: None,
        create_srv_conf: None,
        merge_srv_conf: None,
        create_loc_conf: None,
        merge_loc_conf: None,
    };

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_async_request_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_async_request_module: nginx_sys::ngx_module_t = nginx_sys::ngx_module_t {
    ctx: core::ptr::addr_of!(NGX_HTTP_ASYNC_REQUEST_MODULE_CTX) as _,
    type_: nginx_sys::NGX_HTTP_MODULE as _,
    ..nginx_sys::ngx_module_t::default()
};

struct Module;

impl HttpModule for Module {
    fn module() -> &'static nginx_sys::ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_async_request_module) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut nginx_sys::ngx_conf_t) -> ngx_int_t {
        // SAFETY: this function is called with non-NULL cf always
        let cf = unsafe { &mut *cf };
        add_phase_handler::<SampleAsyncHandler>(cf)
            .map_or(nginx_sys::NGX_ERROR as _, |_| nginx_sys::NGX_OK as _)
    }
}
