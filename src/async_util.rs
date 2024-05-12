use std::future::Future;
use tokio::runtime::Handle;
use tokio::task;

pub fn call_async<F>(f: F) -> F::Output
where
    F: Future,
{
    task::block_in_place(move || Handle::current().block_on(async move { f.await }))
}
