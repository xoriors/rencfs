use std::error::Error;
use std::string::ToString;
use std::sync::{Arc, Weak};
use std::time::Duration;

use retainer::Cache;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

const KEY: &str = "key";

pub trait Provider<T, E: Error>: Send + Sync + 'static {
    fn provide(&self) -> Result<T, E>;
}

pub struct ExpireValue<T: Send + Sync + 'static, E: Error, P: Provider<T, E>> {
    cache: Arc<Cache<String, Arc<T>>>,
    weak: RwLock<Option<Weak<T>>>,
    monitor: Option<JoinHandle<()>>,
    provider: P,
    duration: Duration,
    _marker: std::marker::PhantomData<E>,
}

impl<T: Send + Sync + 'static, E: Error + 'static, P: Provider<T, E>> ExpireValue<T, E, P> {
    pub async fn new(provider: P, duration: Duration) -> Self {
        let mut s = Self {
            cache: Arc::new(Cache::new()),
            weak: RwLock::new(None),
            monitor: None,
            provider,
            duration,
            _marker: Default::default(),
        };
        let clone = s.cache.clone();
        s.monitor = Some(tokio::spawn(async move {
            clone.monitor(4, 0.25, duration).await
        }));

        s
    }

    pub async fn get(&self) -> Result<Arc<T>, E> {
        if let Some(value) = self.get_from_ref_or_cache().await {
            return Ok(value);
        }

        let mut weak = self.weak.write().await;
        let value = self.provider.provide()?;
        let v = Arc::new(value);
        self.cache
            .insert(KEY.to_string(), v.clone(), self.duration)
            .await;
        *weak = Some(Arc::downgrade(&v));

        Ok(v)
    }

    async fn get_from_ref_or_cache(&self) -> Option<Arc<T>> {
        if let Some(ref weak) = *self.weak.read().await {
            // try to take it from weak ref
            if let Some(ref v) = weak.upgrade() {
                return Some(v.clone());
            } else {
                // try to take it from cache
                if let Some(v) = self.cache.get(&KEY.to_string()).await {
                    return Some(Arc::clone(&v));
                }
            }
        }
        None
    }

    pub async fn clear(&self) {
        self.cache.clear().await;
    }
}

impl<T: Send + Sync + 'static, E: Error, P: Provider<T, E>> Drop for ExpireValue<T, E, P> {
    fn drop(&mut self) {
        if let Some(ref monitor) = self.monitor {
            monitor.abort();
        }
    }
}
