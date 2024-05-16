use std::future::Future;

pub fn block_on<F: Future>(future: F, worker_threads: usize) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}
