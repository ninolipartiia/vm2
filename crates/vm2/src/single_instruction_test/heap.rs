use std::ops::Index;

use arbitrary::Arbitrary;
use primitive_types::U256;
use zksync_vm2_interface::HeapId;

use super::mock_array::MockRead;

#[derive(Debug, Clone)]
pub struct Heap {
    pub(crate) read: MockRead<u32, [u8; 32]>,
    pub(crate) write: Option<(u32, U256)>,
}

impl Heap {
    /// An empty heap: every read returns zero, no write recorded.
    pub fn empty() -> Self {
        Self {
            read: MockRead::new([0u8; 32]),
            write: None,
        }
    }
}

#[allow(clippy::unused_self)] // to align signatures with real implementation
impl Heap {
    fn write_u256(&mut self, start_address: u32, value: U256) {
        assert!(self.write.is_none());
        self.write = Some((start_address, value));
    }

    fn write_bytes(&mut self, _start_address: u32, _bytes: &[u8]) {
        // Intentionally not recorded into `self.write`. The only production caller of
        // `Heaps::write_bytes` is `materialize_decommit_page`, which writes a callee's
        // bytecode into a fresh code page during a far call. zk_evm's `MockDecommitter`
        // is a no-op that never touches memory, so recording on the vm2 side would
        // make the symmetric heap-write comparator (`UniversalVmState::heap_write`)
        // diverge against zk_evm's `None`. Decommit-write equivalence is a separate
        // (currently uncovered) blind spot — see claude_overview/fuzzer_blind_spots.md.
        //
        // User-level writes (`HeapWrite` / `AuxHeapWrite` / `PointerWrite` opcodes) all
        // go through `Heaps::write_u256`, which is unaffected and still records.
    }

    pub(crate) fn read_byte(&self, _: u32) -> u8 {
        unimplemented!()
    }

    pub(crate) fn read_u256(&self, start_address: u32) -> U256 {
        assert!(self.write.is_none());
        U256::from_little_endian(self.read.get(start_address))
    }

    pub(crate) fn read_u256_partially(&self, range: std::ops::Range<u32>) -> U256 {
        assert!(self.write.is_none());
        let mut result = *self.read.get(range.start);
        for byte in &mut result[0..32 - range.len()] {
            *byte = 0;
        }
        U256::from_little_endian(&result)
    }

    pub(crate) fn read_range_big_endian(&self, _: std::ops::Range<u32>) -> Vec<u8> {
        // This is wrong, but this method is only used to get the final return value.
        vec![]
    }
}

impl<'a> Arbitrary<'a> for Heap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            read: u.arbitrary()?,
            write: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Heaps {
    #[allow(dead_code)] // For API compatibility with real implementation.
    heap_id: HeapId,
    pub(crate) read: MockRead<HeapId, Heap>,
}

impl Heaps {
    /// Empty heaps tagged with the given identifier — all reads return zero.
    ///
    /// Used by the differential-regressions test crate to build a deterministic
    /// initial state without going through `Arbitrary`.
    pub fn empty(heap_id: HeapId) -> Self {
        Self {
            heap_id,
            read: MockRead::new(Heap::empty()),
        }
    }
}

#[allow(clippy::unused_self)] // to align signatures with real implementation
impl Heaps {
    pub(crate) fn new(_: &[u8]) -> Self {
        unimplemented!("Should use arbitrary heap, not fresh heap in testing.")
    }

    #[allow(dead_code)] // For API compatibility with real implementation.
    pub(crate) fn allocate(&mut self) -> HeapId {
        self.heap_id
    }

    pub(crate) fn allocate_at(&mut self, page: HeapId) -> HeapId {
        page
    }

    #[allow(dead_code)] // For API compatibility with real implementation.
    pub(crate) fn allocate_with_content(&mut self, content: &[u8]) -> HeapId {
        let id = self.allocate();
        self.read
            .get_mut(id)
            .write_u256(0, U256::from_big_endian(content));
        id
    }

    #[allow(dead_code)] // For API compatibility with real implementation.
    pub(crate) fn allocate_with_content_at(&mut self, page: HeapId, content: &[u8]) -> HeapId {
        self.read.get_mut(page).write_bytes(0, content);
        page
    }

    pub(crate) fn deallocate(&mut self, _: HeapId) {}

    pub(crate) fn from_id(
        heap_id: HeapId,
        u: &mut arbitrary::Unstructured<'_>,
    ) -> arbitrary::Result<Heaps> {
        Ok(Heaps {
            heap_id,
            read: u.arbitrary()?,
        })
    }

    pub fn write_u256(&mut self, heap: HeapId, start_address: u32, value: U256) {
        self.read.get_mut(heap).write_u256(start_address, value);
    }

    pub(crate) fn write_bytes(&mut self, heap: HeapId, start_address: u32, bytes: &[u8]) {
        self.read.get_mut(heap).write_bytes(start_address, bytes);
    }

    pub(crate) fn snapshot(&self) -> (usize, usize) {
        unimplemented!()
    }

    pub(crate) fn rollback(&mut self, _: (usize, usize)) {
        unimplemented!()
    }

    pub(crate) fn dynamic_len(&self) -> usize {
        unimplemented!()
    }

    pub(crate) fn truncate_dynamic_to(&mut self, _: usize) {
        unimplemented!()
    }

    pub(crate) fn delete_history(&mut self) {
        unimplemented!()
    }
}

impl Index<HeapId> for Heaps {
    type Output = Heap;

    fn index(&self, index: HeapId) -> &Self::Output {
        self.read.get(index)
    }
}

impl PartialEq for Heaps {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}
