use arbitrary::Arbitrary;
use primitive_types::{H160, U256};
use zksync_vm2_interface::Tracer;

use super::mock_array::MockRead;
use crate::{Program, StorageInterface, StorageSlot, World};

#[derive(Debug, Arbitrary, Clone)]
pub struct MockWorld {
    storage_slot: MockRead<(H160, U256), Option<U256>>,
}

impl MockWorld {
    /// Builds a [`MockWorld`] that returns `value` for any storage slot read.
    ///
    /// `MockRead` only stores a single value per type (see [`super::mock_array`]),
    /// so all reads from this world return the same value — exactly what the
    /// AFL fuzz harness relies on so that vm2 and `zk_evm` see identical reads.
    pub fn with_storage_slot(value: Option<U256>) -> Self {
        Self {
            storage_slot: MockRead::new(value),
        }
    }
}

impl<T: Tracer> World<T> for MockWorld {
    fn decommit(&mut self, _hash: U256) -> Program<T, Self> {
        Program::for_decommit()
    }

    fn decommit_code(&mut self, _hash: U256) -> Vec<u8> {
        vec![0; 32]
    }
}

impl StorageInterface for MockWorld {
    fn read_storage(&mut self, contract: H160, key: U256) -> StorageSlot {
        let value = *self.storage_slot.get((contract, key));
        StorageSlot {
            value: value.unwrap_or_default(),
            is_write_initial: value.is_none(),
        }
    }

    fn cost_of_writing_storage(&mut self, _: StorageSlot, _: U256) -> u32 {
        50
    }

    fn is_free_storage_slot(&self, _: &H160, _: &U256) -> bool {
        false
    }
}
