use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

type Value<V> = (Arc<V>, Arc<AtomicUsize>);
pub struct ArcHashMap<K, V>
where
    K: Eq + Hash,
{
    map: RwLock<HashMap<K, Value<V>>>,
}

pub struct Holder<V> {
    val: Arc<V>,
    rc: Arc<AtomicUsize>,
}

impl<V> Drop for Holder<V> {
    fn drop(&mut self) {
        self.rc.fetch_sub(1, Ordering::SeqCst);
        // debug!(remaining = self.rc.load(Ordering::SeqCst), "Dropping guard");
    }
}

impl<V> Deref for Holder<V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<K: Eq + Hash, V> Default for ArcHashMap<K, V> {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash, V> ArcHashMap<K, V> {
    pub fn insert(&self, key: K, value: V) -> Holder<V> {
        self.purge();
        self.get_or_insert_with(key, || value)
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn get(&self, key: &K) -> Option<Holder<V>> {
        self.purge();
        Self::get_internal(self.map.read().expect("cannot obtain lock").get(key))
    }

    fn get_internal(v: Option<&Value<V>>) -> Option<Holder<V>> {
        if let Some((v, rc)) = v {
            rc.fetch_add(1, Ordering::SeqCst);
            return Some(Holder {
                val: v.clone(),
                rc: rc.clone(),
            });
        }
        None
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn get_or_insert_with<F>(&self, key: K, f: F) -> Holder<V>
    where
        F: FnOnce() -> V,
    {
        self.purge();
        let mut map = self.map.write().expect("cannot obtain lock");
        Self::get_internal(Some(
            map.entry(key)
                .or_insert_with(|| (Arc::new(f()), Arc::new(AtomicUsize::new(0)))),
        ))
        .unwrap()
    }

    fn purge(&self) {
        let mut map = self.map.write().unwrap();
        map.retain(|_, v| v.1.load(Ordering::SeqCst) > 0);
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn len(&self) -> usize {
        self.purge();
        self.map.read().expect("cannot obtain lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arc_hashmap() {
        let m = ArcHashMap::default();
        {
            let v = m.insert(1, 2);
            assert_eq!(*v, 2);
            assert_eq!(m.len(), 1);
            m.insert(2, 3);
            assert_eq!(m.len(), 1);
            let v = m.get_or_insert_with(3, || 4);
            assert_eq!(*v, 4);
            assert_eq!(m.len(), 2);
        }
        assert_eq!(m.len(), 0);
    }
}
