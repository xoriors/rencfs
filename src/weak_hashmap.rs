use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Weak};

pub struct WeakValueHashMap<K, V>
    where
        K: Eq + Hash,
{
    map: HashMap<K, Weak<V>>,
}

impl<K: Eq + Hash, V> WeakValueHashMap<K, V> {
    pub fn new() -> Self {
        WeakValueHashMap {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: K, value: Arc<V>) {
        self.purge();
        self.map.insert(key, Arc::downgrade(&value));
    }

    pub fn get(&mut self, key: &K) -> Option<Arc<V>> {
        self.purge();
        self.map.get(key).and_then(|v| v.upgrade())
    }

    pub fn get_or_insert_with<F>(&mut self, key: K, f: F) -> Arc<V>
        where
            F: FnOnce() -> Arc<V>,
    {
        self.purge();
        let weak = self.map.entry(key).or_insert_with(|| Weak::new());
        weak.upgrade().unwrap_or_else(|| {
            let value = f();
            *weak = Arc::downgrade(&value);
            value
        })
    }

    fn purge(&mut self) {
        self.map.retain(|_, v| v.strong_count() != 0);
    }
}