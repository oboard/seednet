//! Overlay IP allocation and collision detection.
//!
//! Each device's overlay IP is **deterministically** derived from its Ed25519
//! public key using `derive_overlay_addr` (in `seednet-crypto`). This module
//! provides the allocation logic including collision resolution and an
//! allocation table for tracking assigned addresses.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use seednet_common::{OverlayAddr, PeerId, OVERLAY_SUBNET_BASE, OVERLAY_SUBNET_PREFIX};
use seednet_crypto::derive_overlay_addr;

#[derive(Clone, Debug)]
pub struct Allocation {
    pub peer_id: PeerId,
    pub overlay: OverlayAddr,
    pub slot: u8,
}

#[derive(Clone, Debug, Default)]
pub struct AllocationTable {
    allocations: HashMap<PeerId, Allocation>,
    by_ip: HashMap<Ipv4Addr, PeerId>,
}

impl AllocationTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allocate(&mut self, peer_id: PeerId) -> OverlayAddr {
        if let Some(existing) = self.allocations.get(&peer_id) {
            return existing.overlay;
        }

        let base_addr = derive_overlay_addr(&peer_id);
        let mut slot: u8 = 0;
        let mut addr = base_addr;

        while self.by_ip.contains_key(&addr.ip()) {
            slot += 1;
            if slot == 0 {
                break;
            }
            addr = self.fallback_addr(&base_addr, slot);
        }

        let allocation = Allocation {
            peer_id,
            overlay: addr,
            slot,
        };
        self.by_ip.insert(addr.ip(), peer_id);
        self.allocations.insert(peer_id, allocation);
        addr
    }

    pub fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<&PeerId> {
        self.by_ip.get(&ip)
    }

    pub fn lookup_by_peer(&self, peer_id: &PeerId) -> Option<&Allocation> {
        self.allocations.get(peer_id)
    }

    pub fn remove(&mut self, peer_id: &PeerId) -> Option<Allocation> {
        let alloc = self.allocations.remove(peer_id)?;
        self.by_ip.remove(&alloc.overlay.ip());
        Some(alloc)
    }

    pub fn len(&self) -> usize {
        self.allocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allocations.is_empty()
    }

    pub fn all_allocations(&self) -> impl Iterator<Item = &Allocation> {
        self.allocations.values()
    }

    fn fallback_addr(&self, base: &OverlayAddr, slot: u8) -> OverlayAddr {
        let octets = base.ip().octets();
        let new_octet4 = octets[3].wrapping_add(slot);
        OverlayAddr::new(Ipv4Addr::new(octets[0], octets[1], octets[2], new_octet4))
    }
}

pub fn resolve_overlay_ip(peer_id: &PeerId) -> OverlayAddr {
    derive_overlay_addr(peer_id)
}

pub fn is_in_overlay_subnet(addr: OverlayAddr) -> bool {
    let _mask = subnet_mask_u32(OVERLAY_SUBNET_PREFIX);
    (u32::from(addr.ip()) & _mask) == (u32::from(OVERLAY_SUBNET_BASE) & _mask)
}

fn subnet_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 { return 0; }
    if prefix >= 32 { return !0u32; }
    !0u32 << (32 - prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer_id(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    #[test]
    fn deterministic_allocation() {
        let id = test_peer_id(42);
        let addr = resolve_overlay_ip(&id);
        assert_eq!(addr, derive_overlay_addr(&id));
    }

    #[test]
    fn allocation_table_basic() {
        let mut table = AllocationTable::new();
        let id = test_peer_id(1);
        let addr = table.allocate(id);
        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup_by_peer(&id).unwrap().overlay, addr);
        assert_eq!(table.lookup_by_ip(addr.ip()), Some(&id));
    }

    #[test]
    fn duplicate_allocate_returns_same() {
        let mut table = AllocationTable::new();
        let id = test_peer_id(1);
        let a1 = table.allocate(id);
        let a2 = table.allocate(id);
        assert_eq!(a1, a2);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn remove_deallocation() {
        let mut table = AllocationTable::new();
        let id = test_peer_id(1);
        let addr = table.allocate(id);
        let removed = table.remove(&id).unwrap();
        assert_eq!(removed.overlay, addr);
        assert!(table.is_empty());
        assert!(table.lookup_by_ip(addr.ip()).is_none());
    }

    #[test]
    fn check_overlay_subnet() {
        let in_net = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        let out_net = OverlayAddr::new(Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_in_overlay_subnet(in_net));
        assert!(!is_in_overlay_subnet(out_net));
    }

    #[test]
    fn collision_resolution_falls_back() {
        let mut table = AllocationTable::new();
        let id_a = test_peer_id(1);
        let id_b = test_peer_id(2);
        let addr_a = table.allocate(id_a);

        let mut raw_b = [0u8; 32];
        raw_b.copy_from_slice(id_b.as_bytes());
        let derived_b = derive_overlay_addr(&id_b);

        let addr_b = table.allocate(id_b);
        if derived_b == addr_a {
            assert_ne!(addr_b, addr_a, "collision should be resolved");
        }
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn many_allocations_no_panic() {
        let mut table = AllocationTable::new();
        for i in 1u8..=50 {
            let id = PeerId::from_bytes([i; 32]);
            let _addr = table.allocate(id);
        }
        assert_eq!(table.len(), 50);
    }

    #[test]
    fn all_allocations_in_subnet() {
        let mut table = AllocationTable::new();
        for i in 1u8..=100 {
            let id = PeerId::from_bytes([i; 32]);
            let addr = table.allocate(id);
            assert!(is_in_overlay_subnet(addr), "addr {} not in overlay subnet", addr);
        }
    }
}
