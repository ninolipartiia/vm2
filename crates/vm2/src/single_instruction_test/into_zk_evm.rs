use std::sync::Arc;

use primitive_types::U256;
use zk_evm::{
    abstractions::{DecommittmentProcessor, Memory, MemoryType, PrecompilesProcessor, Storage},
    aux_structures::PubdataCost,
    block_properties::BlockProperties,
    reference_impls::event_sink::InMemoryEventSink,
    tracing,
    vm_state::{Version, VmState},
    witness_trace::VmWitnessTracer,
};
use zk_evm_abstractions::vm::EventSink;
use zkevm_opcode_defs::{decoding::EncodingModeProduction, TRANSIENT_STORAGE_AUX_BYTE};
use zksync_vm2_interface::Tracer;

use super::{stack::Stack, state_to_zk_evm::vm2_state_to_zk_evm_state, MockWorld};
use crate::{StorageInterface, VirtualMachine, World};

type ZkEvmState = VmState<
    MockWorldWrapper,
    MockMemory,
    InMemoryEventSink,
    NoOracle,
    MockDecommitter,
    NoOracle,
    8,
    EncodingModeProduction,
>;

pub fn vm2_to_zk_evm<T: Tracer, W: World<T>>(
    vm: &VirtualMachine<T, W>,
    world: MockWorld,
) -> ZkEvmState {
    let mut event_sink = InMemoryEventSink::new();
    event_sink.start_frame(zk_evm::aux_structures::Timestamp(0));

    // Pre-execution this is `None` (no heap access has happened yet); post-execution
    // this is populated from vm2's recorded write so the universal-state projection
    // built from vm2 can be compared against zk_evm's observed write.
    let heap_write_observed = vm2_recorded_heap_write(vm);

    VmState {
        local_state: vm2_state_to_zk_evm_state(&vm.state),
        block_properties: BlockProperties {
            default_aa_code_hash: U256::from_big_endian(&vm.settings.default_aa_code_hash),
            evm_emulator_code_hash: U256::from_big_endian(&vm.settings.evm_interpreter_code_hash),
            zkporter_is_available: false,
        },
        storage: MockWorldWrapper(world),
        memory: MockMemory {
            code_page: vm.state.current_frame.program.code_page().clone(),
            stack: *vm.state.current_frame.stack.clone(),
            heap_read: None,
            heap_write_expected: None,
            heap_write_observed,
        },
        event_sink,
        precompiles_processor: NoOracle,
        decommittment_processor: MockDecommitter,
        witness_tracer: NoOracle,
        version: Version::Version27,
    }
}

fn vm2_recorded_heap_write<T, W>(vm: &VirtualMachine<T, W>) -> Option<ExpectedHeapValue> {
    let (heapid, heap) = vm.state.heaps.read.read_that_happened()?;
    let (start_index, value_u256) = heap.write?;
    let mut value = [0u8; 32];
    value_u256.to_big_endian(&mut value);
    Some(ExpectedHeapValue {
        heap: heapid.as_u32(),
        start_index,
        value,
    })
}

pub fn add_heap_to_zk_evm<T, W>(
    zk_evm: &mut ZkEvmState,
    vm_after_execution: &VirtualMachine<T, W>,
) {
    if let Some((heapid, heap)) = vm_after_execution.state.heaps.read.read_that_happened() {
        if let Some((start_index, mut value)) = heap.read.read_that_happened() {
            value.reverse();

            zk_evm.memory.heap_read = Some(ExpectedHeapValue {
                heap: heapid.as_u32(),
                start_index,
                value,
            });
        }
        if let Some((start_index, value_u256)) = heap.write {
            let mut value = [0; 32];
            value_u256.to_big_endian(&mut value);

            zk_evm.memory.heap_write_expected = Some(ExpectedHeapValue {
                heap: heapid.as_u32(),
                start_index,
                value,
            });
        }
    }
}

#[derive(Debug)]
pub struct MockMemory {
    code_page: Arc<[U256]>,
    stack: Stack,
    heap_read: Option<ExpectedHeapValue>,
    /// vm2's recorded write, propagated via [`add_heap_to_zk_evm`] before zk_evm
    /// runs. Used in `execute_partial_query` to fail-fast when zk_evm's write
    /// disagrees with vm2's.
    heap_write_expected: Option<ExpectedHeapValue>,
    /// The write zk_evm actually issued during its cycle. Recorded by
    /// `execute_partial_query` and surfaced through `UniversalVmState` so the
    /// post-cycle comparator can also detect "vm2 wrote but zk_evm didn't."
    ///
    /// When zk_evm splits a misaligned vm2 write into two word-aligned
    /// `MemoryQuery`s, the per-query bytes are merged into a single recording
    /// whose `start_index` matches vm2's, so the structured comparison stays
    /// byte-exact regardless of zk_evm's word alignment.
    pub(crate) heap_write_observed: Option<ExpectedHeapValue>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedHeapValue {
    pub(crate) heap: u32,
    pub(crate) start_index: u32,
    pub(crate) value: [u8; 32],
}

impl ExpectedHeapValue {
    /// Returns a new U256 that contains data from the heap value and zero elsewhere.
    /// One arbitrary heap value is not enough for `zk_evm` because it reads two U256s to read one U256.
    fn partially_overlapping_u256(&self, start: u32) -> U256 {
        let mut read = [0; 32];
        for i in 0..32 {
            if start + i >= self.start_index {
                let j = start + i - self.start_index;
                if j < 32 {
                    read[i as usize] = self.value[j as usize];
                }
            }
        }
        U256::from_big_endian(&read)
    }
}

impl Memory for MockMemory {
    fn execute_partial_query(
        &mut self,
        _: u32,
        mut query: zk_evm::aux_structures::MemoryQuery,
    ) -> zk_evm::aux_structures::MemoryQuery {
        match query.location.memory_type {
            MemoryType::Stack => {
                #[allow(clippy::cast_possible_truncation)] // intentional
                let slot = query.location.index.0 as u16;
                if query.rw_flag {
                    self.stack.set(slot, query.value);
                    if query.value_is_pointer {
                        self.stack.set_pointer_flag(slot);
                    } else {
                        self.stack.clear_pointer_flag(slot);
                    }
                } else {
                    query.value = self.stack.get(slot);
                    query.value_is_pointer = self.stack.get_pointer_flag(slot);
                }
                query
            }
            MemoryType::Heap | MemoryType::AuxHeap | MemoryType::FatPointer => {
                if query.rw_flag {
                    let heap = self.heap_write_expected.unwrap();
                    assert_eq!(heap.heap, query.location.page.0);

                    assert_eq!(
                        query.value,
                        heap.partially_overlapping_u256(query.location.index.0 * 32)
                    );

                    // Reconstruct vm2's logical 32-byte write from zk_evm's per-word
                    // queries. A misaligned vm2 write spans two zk_evm word queries;
                    // each query overlays its bytes onto the observed value at the
                    // correct offset relative to vm2's `start_index`. After all queries,
                    // `heap_write_observed` matches vm2's `(start_index, value)` exactly.
                    let observed =
                        self.heap_write_observed.get_or_insert(ExpectedHeapValue {
                            heap: query.location.page.0,
                            start_index: heap.start_index,
                            value: [0u8; 32],
                        });
                    let query_byte_start = query.location.index.0 * 32;
                    let mut query_bytes = [0u8; 32];
                    query.value.to_big_endian(&mut query_bytes);
                    for i in 0..32u32 {
                        let abs_byte = query_byte_start + i;
                        if abs_byte >= observed.start_index {
                            let j = abs_byte - observed.start_index;
                            if j < 32 {
                                observed.value[j as usize] = query_bytes[i as usize];
                            }
                        }
                    }
                } else if let Some(heap) = self.heap_read {
                    // ^ Writes read the heap too, but they are just fed zeroes

                    assert_eq!(query.location.page.0, heap.heap);

                    query.value = heap.partially_overlapping_u256(query.location.index.0 * 32);
                }
                query
            }
            _ => todo!(),
        }
    }

    fn specialized_code_query(
        &mut self,
        _: u32,
        _query: zk_evm::aux_structures::MemoryQuery,
    ) -> zk_evm::aux_structures::MemoryQuery {
        todo!()
    }

    fn read_code_query(
        &self,
        _: u32,
        mut query: zk_evm::aux_structures::MemoryQuery,
    ) -> zk_evm::aux_structures::MemoryQuery {
        // Code page read, instruction reads don't happen because the code word cache has been set up
        query.value = self
            .code_page
            .get(query.location.index.0 as usize)
            .copied()
            .unwrap_or_default();
        query
    }
}

#[derive(Debug)]
pub struct MockWorldWrapper(MockWorld);

impl Storage for MockWorldWrapper {
    fn get_access_refund(
        &mut self, // to avoid any hacks inside, like prefetch
        _: u32,
        _partial_query: &zk_evm::aux_structures::LogQuery,
    ) -> zk_evm::abstractions::StorageAccessRefund {
        zk_evm::abstractions::StorageAccessRefund::Cold
    }

    fn execute_partial_query(
        &mut self,
        _: u32,
        mut query: zk_evm::aux_structures::LogQuery,
    ) -> (zk_evm::aux_structures::LogQuery, PubdataCost) {
        if query.rw_flag {
            (query, PubdataCost(0))
        } else {
            query.read_value = if query.aux_byte == TRANSIENT_STORAGE_AUX_BYTE {
                U256::zero()
            } else {
                self.0.read_storage_value(query.address, query.key)
            };
            (query, PubdataCost(0))
        }
    }

    fn start_frame(&mut self, _: zk_evm::aux_structures::Timestamp) {}

    fn finish_frame(&mut self, _: zk_evm::aux_structures::Timestamp, _panicked: bool) {}

    fn start_new_tx(&mut self, _: zk_evm::aux_structures::Timestamp) {}
}

#[derive(Debug)]
pub struct MockDecommitter;

impl DecommittmentProcessor for MockDecommitter {
    fn prepare_to_decommit(
        &mut self,
        _: u32,
        mut partial_query: zk_evm::aux_structures::DecommittmentQuery,
    ) -> anyhow::Result<zk_evm::aux_structures::DecommittmentQuery> {
        partial_query.is_fresh = true;
        Ok(partial_query)
    }

    fn decommit_into_memory<M: Memory>(
        &mut self,
        _: u32,
        _partial_query: zk_evm::aux_structures::DecommittmentQuery,
        _memory: &mut M,
    ) -> anyhow::Result<Option<Vec<U256>>> {
        Ok(None)
    }
}

#[derive(Debug)]
pub struct NoTracer;

impl tracing::Tracer for NoTracer {
    type SupportedMemory = MockMemory;

    fn before_decoding(
        &mut self,
        _: zk_evm::tracing::VmLocalStateData<'_, 8, EncodingModeProduction>,
        _: &Self::SupportedMemory,
    ) {
    }

    fn after_decoding(
        &mut self,
        _: zk_evm::tracing::VmLocalStateData<'_, 8, EncodingModeProduction>,
        _: zk_evm::tracing::AfterDecodingData<8, EncodingModeProduction>,
        _: &Self::SupportedMemory,
    ) {
    }

    fn before_execution(
        &mut self,
        _: zk_evm::tracing::VmLocalStateData<'_, 8, EncodingModeProduction>,
        _: zk_evm::tracing::BeforeExecutionData<8, EncodingModeProduction>,
        _: &Self::SupportedMemory,
    ) {
    }

    fn after_execution(
        &mut self,
        _: zk_evm::tracing::VmLocalStateData<'_, 8, EncodingModeProduction>,
        _: zk_evm::tracing::AfterExecutionData<8, EncodingModeProduction>,
        _: &Self::SupportedMemory,
    ) {
    }
}

#[derive(Debug, Clone)]
pub struct NoOracle;

impl PrecompilesProcessor for NoOracle {
    fn execute_precompile<M: Memory>(
        &mut self,
        _: u32,
        _: zk_evm::aux_structures::LogQuery,
        _: &mut M,
    ) -> Option<(
        Vec<zk_evm::aux_structures::MemoryQuery>,
        Vec<zk_evm::aux_structures::MemoryQuery>,
        zk_evm::abstractions::PrecompileCyclesWitness,
    )> {
        unimplemented!()
    }

    fn start_frame(&mut self) {}

    fn finish_frame(&mut self, _: bool) {}
}

impl VmWitnessTracer<8, EncodingModeProduction> for NoOracle {
    fn start_new_execution_cycle(
        &mut self,
        _: &zk_evm::vm_state::VmLocalState<8, EncodingModeProduction>,
    ) {
    }

    fn end_execution_cycle(
        &mut self,
        _: &zk_evm::vm_state::VmLocalState<8, EncodingModeProduction>,
    ) {
    }

    fn add_memory_query(&mut self, _: u32, _: zk_evm::aux_structures::MemoryQuery) {}

    fn record_refund_for_query(
        &mut self,
        _: u32,
        _: zk_evm::aux_structures::LogQuery,
        _: zk_evm::abstractions::StorageAccessRefund,
    ) {
    }

    fn add_log_query(&mut self, _: u32, _: zk_evm::aux_structures::LogQuery) {}

    fn record_pubdata_cost_for_query(
        &mut self,
        _: u32,
        _: zk_evm::aux_structures::LogQuery,
        _: PubdataCost,
    ) {
    }

    fn prepare_for_decommittment(&mut self, _: u32, _: zk_evm::aux_structures::DecommittmentQuery) {
    }

    fn execute_decommittment(
        &mut self,
        _: u32,
        _: zk_evm::aux_structures::DecommittmentQuery,
        _: Vec<U256>,
    ) {
    }

    fn add_precompile_call_result(
        &mut self,
        _: u32,
        _: zk_evm::aux_structures::LogQuery,
        _: Vec<zk_evm::aux_structures::MemoryQuery>,
        _: Vec<zk_evm::aux_structures::MemoryQuery>,
        _: zk_evm::abstractions::PrecompileCyclesWitness,
    ) {
    }

    fn add_revertable_precompile_call(&mut self, _: u32, _: zk_evm::aux_structures::LogQuery) {}

    fn start_new_execution_context(
        &mut self,
        _: u32,
        _: &zk_evm::vm_state::CallStackEntry<8, EncodingModeProduction>,
        _: &zk_evm::vm_state::CallStackEntry<8, EncodingModeProduction>,
    ) {
    }

    fn finish_execution_context(&mut self, _: u32, _: bool) {}
}
