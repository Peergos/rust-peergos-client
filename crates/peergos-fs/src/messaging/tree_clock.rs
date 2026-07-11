//! `TreeClock` — a generalisation of a vector clock that allows changing group
//! membership, ported from `peergos.shared.messaging.TreeClock`.

use super::id::Id;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeClock {
    pub time: BTreeMap<Id, i64>,
}

impl TreeClock {
    pub fn new(time: BTreeMap<Id, i64>) -> TreeClock {
        TreeClock { time }
    }

    pub fn init(members: &[Id]) -> TreeClock {
        let mut time = BTreeMap::new();
        for m in members {
            time.insert(m.clone(), 0);
        }
        TreeClock::new(time)
    }

    pub fn merge(&self, other: &TreeClock) -> TreeClock {
        let mut res = self.time.clone();
        for (k, v) in &other.time {
            if res.get(k).map(|existing| existing < v).unwrap_or(true) {
                res.insert(k.clone(), *v);
            }
        }
        TreeClock::new(res)
    }

    pub fn is_before_or_equal(&self, b: &TreeClock) -> bool {
        for (id, counter) in &self.time {
            if !b.has_id(id) || *counter > b.get_event_counter(id) {
                return false;
            }
        }
        true
    }

    pub fn has_greater_counter_than(&self, b: &TreeClock) -> bool {
        for (id, counter) in &self.time {
            if b.has_id(id) && *counter > b.get_event_counter(id) {
                return true;
            }
        }
        false
    }

    pub fn is_concurrent_with(&self, b: &TreeClock) -> bool {
        self.has_greater_counter_than(b) && b.has_greater_counter_than(self)
    }

    pub fn remove_member(&self, remover: &Id, to_remove: &Id) -> TreeClock {
        let mut res = self.time.clone();
        res.remove(to_remove);
        let cur = *res.get(remover).unwrap_or(&0);
        res.insert(remover.clone(), cur + 1);
        TreeClock::new(res)
    }

    pub fn with_member(&self, member: Id) -> TreeClock {
        let mut res = self.time.clone();
        res.insert(member, 0);
        TreeClock::new(res)
    }

    pub fn has_id(&self, member: &Id) -> bool {
        self.time.contains_key(member)
    }

    pub fn get_event_counter(&self, member: &Id) -> i64 {
        *self.time.get(member).expect("Id not present in clock!")
    }

    pub fn increment(&self, member: &Id) -> TreeClock {
        let counter = *self.time.get(member).unwrap_or(&0);
        let mut res = self.time.clone();
        res.insert(member.clone(), counter + 1);
        TreeClock::new(res)
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<TreeClock> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor(format!("Incorrect cbor for TreeClock: {cbor:?}")))?;
        let mut time = BTreeMap::new();
        for m in list {
            let inner = m
                .as_list()
                .ok_or_else(|| Error::Cbor("TreeClock entry not a list".into()))?;
            let longs = inner
                .iter()
                .map(|i| i.as_long().ok_or_else(|| Error::Cbor("TreeClock entry not a long".into())))
                .collect::<Result<Vec<i64>>>()?;
            if longs.is_empty() {
                return Err(Error::Cbor("Empty TreeClock entry".into()));
            }
            let (counter, id_parts) = longs.split_last().unwrap();
            let id = Id::new(id_parts.iter().map(|v| *v as i32).collect());
            time.insert(id, *counter);
        }
        Ok(TreeClock::new(time))
    }
}

impl Cborable for TreeClock {
    fn to_cbor(&self) -> CborObject {
        let entries = self
            .time
            .iter()
            .map(|(id, counter)| {
                let mut mapping: Vec<CborObject> =
                    id.id.iter().map(|i| CborObject::Long(*i as i64)).collect();
                mapping.push(CborObject::Long(*counter));
                CborObject::List(mapping)
            })
            .collect();
        CborObject::List(entries)
    }
}

impl std::fmt::Display for TreeClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self.time.iter().map(|(k, v)| format!("{k}:{v}")).collect();
        write!(f, "{}", parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(parts: &[i32]) -> Id {
        Id::new(parts.to_vec())
    }

    #[test]
    fn increment_and_before() {
        let a = TreeClock::init(&[id(&[0]), id(&[1])]);
        let b = a.increment(&id(&[0]));
        assert!(a.is_before_or_equal(&b));
        assert!(!b.is_before_or_equal(&a));
    }

    #[test]
    fn concurrent() {
        let base = TreeClock::init(&[id(&[0]), id(&[1])]);
        let a = base.increment(&id(&[0]));
        let b = base.increment(&id(&[1]));
        assert!(a.is_concurrent_with(&b));
        let merged = a.merge(&b);
        assert!(a.is_before_or_equal(&merged));
        assert!(b.is_before_or_equal(&merged));
    }

    #[test]
    fn cbor_roundtrip() {
        let mut clock = TreeClock::init(&[id(&[0]), id(&[0, 1])]);
        clock = clock.increment(&id(&[0]));
        assert_eq!(TreeClock::from_cbor(&clock.to_cbor()).unwrap(), clock);
    }
}
