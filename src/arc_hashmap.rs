use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct ArcHashMap<K, V>
    where
        K: Eq + Hash + Copy,
{
    map: HashMap<K, (Arc<V>, Arc<AtomicUsize>)>,
}

pub struct Guard<V>
{
    val: Arc<V>,
    rc: Arc<AtomicUsize>,
}

impl<V> Drop for Guard<V> {
    fn drop(&mut self) {
        self.rc.fetch_sub(1, Ordering::SeqCst);
        // debug!(remaining = self.rc.load(Ordering::SeqCst), "Dropping guard");
    }
}

impl<V> Deref for Guard<V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &*self.val
    }
}

impl<K: Eq + Hash + Copy, V> ArcHashMap<K, V> {
    pub fn new() -> Self {
        ArcHashMap {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Guard<V> {
        self.purge();
        self.get_or_insert_with(key, || value)
    }

    pub fn get<'a>(&mut self, key: &K) -> Option<Guard<V>> {
        let v = self.map.get_mut(key);
        if let Some((v, rc)) = v {
            rc.fetch_add(1, Ordering::SeqCst);
            return Some(Guard { val: v.clone(), rc: rc.clone() });
        }
        self.purge();
        None
    }

    pub fn get_or_insert_with<F>(&mut self, key: K, f: F) -> Guard<V>
        where
            F: FnOnce() -> V,
    {
        self.purge();
        let key2 = key.clone();
        self.map.entry(key).or_insert_with(|| {
            (Arc::new(f()), Arc::new(AtomicUsize::new(1)))
        });
        self.get(&key2).unwrap()
    }

    fn purge(&mut self) {
        let keys = self.map.keys().cloned().collect::<Vec<_>>();
        for k in keys {
            if self.map.get(&k).unwrap().1.load(Ordering::SeqCst) == 0 {
                self.map.remove(&k);
            }
        }
    }

    pub fn len(&mut self) -> usize {
        self.purge();
        self.map.len()
    }
}