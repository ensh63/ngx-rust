use core::{fmt::Display, marker::PhantomData};

use crate::allocator::AllocError;

use crate::http::{HttpModule, Request};

/// Type to manipulate request context for a specific module and context type.
pub struct RequestContext<Module: HttpModule, Context: Sized>(PhantomData<(Module, Context)>);

/// Error type indicating that the module context was not found for a request.
#[derive(Debug)]
pub struct NoContextError;

impl Display for NoContextError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "context not found")
    }
}

impl core::error::Error for NoContextError {}

impl<Module: HttpModule, Context: Sized> RequestContext<Module, Context> {
    fn get_ctx_ptr(r: &Request) -> *mut Context {
        unsafe { *(r.as_ref()).ctx.add(Module::module().ctx_index) }.cast::<Context>()
    }

    /// Check if module context exists for a specific module.
    pub fn exists(r: &Request) -> bool {
        !Self::get_ctx_ptr(r).is_null()
    }

    /// Get module context for a specific module,
    /// returning `None` if the context is not set.
    pub fn get(r: &Request) -> Option<&Context> {
        unsafe { Self::get_ctx_ptr(r).as_ref() }
    }

    /// Set module context for a specific module, returning a mutable reference to the context
    /// or an `AllocError` if allocation fails.
    pub fn set(r: &mut Request, value: Context) -> Result<&mut Context, AllocError> {
        let pool = r.pool();
        let ctx_ptr = pool.allocate::<Context>(value);
        if ctx_ptr.is_null() {
            return Err(AllocError);
        }
        unsafe {
            *(r.as_mut()).ctx.add(Module::module().ctx_index) = ctx_ptr as _;
            Ok(&mut *ctx_ptr)
        }
    }

    /// Set module context for a specific module, returning a mutable reference to the context
    pub fn try_set<F, E>(r: &mut Request, f: F) -> Result<&mut Context, E>
    where
        E: From<AllocError>,
        F: FnOnce(&Request) -> Result<Context, E>,
    {
        let value = f(r)?;
        Self::set(r, value).map_err(E::from)
    }

    /// Modify the module context for a specific module using a provided closure,
    /// returning a reference to the modified context or an error if the context is not found.
    pub fn modify<F>(r: &mut Request, f: F) -> Result<&Context, NoContextError>
    where
        F: FnOnce(&mut Context, &Request),
    {
        unsafe { Self::get_ctx_ptr(r).as_mut() }.map_or(Err(NoContextError), |ctx| {
            f(ctx, r);
            Ok(ctx as &Context)
        })
    }

    /// Modify the module context for a specific module using a provided fallible closure,
    /// returning a reference to the modified context or an error if the context is not found.
    pub fn try_modify<F, E>(r: &mut Request, f: F) -> Result<&Context, E>
    where
        E: From<NoContextError>,
        F: FnOnce(&mut Context, &Request) -> Result<(), E>,
    {
        unsafe { Self::get_ctx_ptr(r).as_mut() }.map_or(Err(E::from(NoContextError)), |ctx| {
            f(ctx, r)?;
            Ok(ctx as &Context)
        })
    }
}
