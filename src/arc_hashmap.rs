use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct ArcHashMap<K, V>
    where
        K: Eq + Hash,
{
    map: Mutex<HashMap<K, (Arc<V>, Arc<AtomicUsize>)>>,
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

impl<K: Eq + Hash, V> ArcHashMap<K, V> {
    pub fn new() -> Self {
        ArcHashMap {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, key: K, value: V) -> Guard<V> {
        self.purge();
        self.get_or_insert_with(key, || value)
    }

    pub fn get<'a>(&self, key: &K) -> Option<Guard<V>> {
        self.purge();
        self.get_internal(self.map.lock().unwrap().get(key))
    }

    pub fn get_internal<'a>(&self, v: Option<&(Arc<V>, Arc<AtomicUsize>)>) -> Option<Guard<V>> {
        if let Some((v, rc)) = v {
            rc.fetch_add(1, Ordering::SeqCst);
            return Some(Guard { val: v.clone(), rc: rc.clone() });
        }
        None
    }

    pub fn get_or_insert_with<F>(&self, key: K, f: F) -> Guard<V>
        where
            F: FnOnce() -> V,
    {
        self.purge();
        let mut map = self.map.lock().unwrap();
        let v = map.entry(key).or_insert_with(|| {
            (Arc::new(f()), Arc::new(AtomicUsize::new(0)))
        });
        self.get_internal(Some(v)).unwrap()
    }

    fn purge(&self) {
        let mut map = self.map.lock().unwrap();
        map.retain(|_, v| v.1.load(Ordering::SeqCst) > 0);
    }

    pub fn len(&self) -> usize {
        self.purge();
        self.map.lock().unwrap().len()
    }
}