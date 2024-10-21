use std::error::Error;
use std::marker::PhantomData;
use std::string::ToString;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use retainer::Cache;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

const KEY: &str = "key";

#[async_trait]
pub trait ValueProvider<T, E: Error + Send + Sync + 'static>: Send + Sync + 'static {
    async fn provide(&self) -> Result<T, E>;
}

/// It keeps the value in memory while it's being used and while there are strong references to it.
///
/// After the specified `duration` it will remove it from internal cache and just keep it while there are strong references to it, after which it will be zeroized and dropped from memory.  
// Helps mitigate against [Cold boot attack](https://en.wikipedia.org/wiki/Cold_boot_attack) by expiring values from memory.
pub struct ExpireValue<
    T: Send + Sync + 'static,
    E: Error + Send + Sync + 'static,
    P: ValueProvider<T, E> + Send + Sync + 'static,
> {
    cache: Arc<Cache<String, Arc<T>>>,
    weak: RwLock<Option<Weak<T>>>,
    monitor: Option<JoinHandle<()>>,
    provider: P,
    duration: Duration,
    _marker: PhantomData<E>,
}

impl<
        T: Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        P: ValueProvider<T, E> + Send + Sync + 'static,
    > ExpireValue<T, E, P>
{
    pub fn new(provider: P, duration: Duration) -> Self {
        let mut s = Self {
            cache: Arc::new(Cache::new()),
            weak: RwLock::new(None),
            monitor: None,
            provider,
            duration,
            _marker: PhantomData {},
        };
        let clone = s.cache.clone();
        s.monitor = Some(tokio::spawn(async move {
            clone.monitor(4, 0.25, duration).await;
        }));

        s
    }

    pub async fn get(&self) -> Result<Arc<T>, E> {
        if let Some(value) = self.get_from_ref_or_cache().await {
            return Ok(value);
        }
        let value = self.provider.provide().await?;
        let v = Arc::new(value);
        self.cache
            .insert(KEY.to_string(), v.clone(), self.duration)
            .await;
        let mut weak = self.weak.write().await;
        *weak = Some(Arc::downgrade(&v));
        Ok(v)
    }

    async fn get_from_ref_or_cache(&self) -> Option<Arc<T>> {
        let lock = self.weak.read().await;
        if let Some(ref weak) = *lock {
            // try to take it from weak ref
            if let Some(ref v) = weak.upgrade() {
                return Some(v.clone());
            }
            // try to take it from cache
            if let Some(v) = self.cache.get(&KEY.to_string()).await {
                return Some(v.clone());
            }
        }
        None
    }

    pub async fn clear(&self) {
        self.cache.clear().await;
    }
}

impl<T: Send + Sync + 'static, E: Error + Send + Sync + 'static, P: ValueProvider<T, E>> Drop
    for ExpireValue<T, E, P>
{
    fn drop(&mut self) {
        if let Some(ref monitor) = self.monitor {
            monitor.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct TestProvider {
        called: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl ValueProvider<String, Infallible> for TestProvider {
        async fn provide(&self) -> Result<String, Infallible> {
            self.called.fetch_add(1, Ordering::SeqCst);
            Ok("test".to_string())
        }
    }

    #[tokio::test]
    async fn test_expire_value() {
        let called = Arc::new(AtomicUsize::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = ExpireValue::new(provider, Duration::from_secs(1));
        let v = expire_value.get().await.unwrap();
        // ensure our value is correct
        assert_eq!(*v, "test");
        // ensure the provider wa called
        assert_eq!(called.load(Ordering::SeqCst), 1);

        // wait for cache to expire
        tokio::time::sleep(Duration::from_secs(2)).await;
        // ensure it's taken from Weak ref
        let _ = expire_value.get().await.unwrap();
        assert_eq!(called.load(Ordering::SeqCst), 1);

        // drop ref so now provider should be called again
        drop(v);
        let _ = expire_value.get().await.unwrap();
        // ensure provider was called again
        assert_eq!(called.load(Ordering::SeqCst), 2);

        // clear cache
        expire_value.clear().await;
        let _ = expire_value.get().await.unwrap();
        // ensure provider was called again
        let called = called.clone();
        assert_eq!(called.load(Ordering::SeqCst), 3)
    }
}
