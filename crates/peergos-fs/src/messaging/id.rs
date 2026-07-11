//! `Id` — a member's position in the chat's invite tree, ported from
//! `peergos.shared.messaging.Id`.
//!
//! Ids in a chat form a tree. The creator is the root, and each member is a child
//! node of the member that invited them. They are fully concurrent — anyone can
//! invite anyone at any time without synchronisation. In the simple case of a
//! fixed group known at creation time these are the same as the indices in a
//! vector clock.

use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id {
    pub id: Vec<i32>,
}

impl Id {
    pub fn new(id: Vec<i32>) -> Id {
        Id { id }
    }

    pub fn single(counter: i32) -> Id {
        Id { id: vec![counter] }
    }

    pub fn creator() -> Id {
        Id::single(0)
    }

    /// A new descendant Id, appending `counter` (`fork`).
    pub fn fork(&self, counter: i32) -> Id {
        let mut descendant = self.id.clone();
        descendant.push(counter);
        Id::new(descendant)
    }

    /// The parent Id, dropping the last component (`parent`).
    pub fn parent(&self) -> Id {
        Id::new(self.id[..self.id.len() - 1].to_vec())
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<Id> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor(format!("Incorrect cbor for Id: {cbor:?}")))?;
        let id = list
            .iter()
            .map(|e| e.as_long().map(|v| v as i32).ok_or_else(|| Error::Cbor("Id component not a long".into())))
            .collect::<Result<Vec<i32>>>()?;
        Ok(Id::new(id))
    }
}

impl Cborable for Id {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(self.id.iter().map(|i| CborObject::Long(*i as i64)).collect())
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self.id.iter().map(|x| x.to_string()).collect();
        write!(f, "[{}]", parts.join(","))
    }
}

impl Ord for Id {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Mirror Id.compare(int[], int[]): compare element-wise over the common
        // prefix, and if one is a prefix of the other the shorter sorts first.
        let common = self.id.len().min(other.id.len());
        for i in 0..common {
            if self.id[i] != other.id[i] {
                return self.id[i].cmp(&other.id[i]);
            }
        }
        self.id.len().cmp(&other.id.len())
    }
}

impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_and_parent() {
        let creator = Id::creator();
        let child = creator.fork(3);
        assert_eq!(child.id, vec![0, 3]);
        assert_eq!(child.parent(), creator);
    }

    #[test]
    fn ordering() {
        assert!(Id::new(vec![0]) < Id::new(vec![0, 0]));
        assert!(Id::new(vec![0, 1]) < Id::new(vec![1]));
        assert!(Id::new(vec![0, 0]) < Id::new(vec![0, 1]));
    }

    #[test]
    fn cbor_roundtrip() {
        let id = Id::new(vec![0, 5, 2]);
        assert_eq!(Id::from_cbor(&id.to_cbor()).unwrap(), id);
    }
}
