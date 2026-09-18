//! WFDMA pointer reset strobes, including the MCU rings used during reinit.
use super::{Mt7981Board, WFDMA0_RX0_DIDX};

impl Mt7981Board {
    pub(super) fn reset_wfdma_tx_pointers(&mut self, mask: u32) {
        // TX register bank starts at +0x300: +0x400 is hardware ring 16.
        for ring in 0..5u32 {
            if mask & (1 << (16 + ring)) != 0 {
                self.wfdma_tx_didx[ring as usize] = 0;
                self.control_regs
                    .insert(0x1802_440c + u64::from(ring) * 16, 0);
            }
        }
        self.wifi.reset_tx_rings(mask);
    }

    pub(super) fn reset_wfdma_rx_pointers(&mut self, mask: u32) {
        for ring in 0..6u32 {
            if mask & (1 << ring) != 0 {
                self.control_regs
                    .insert(WFDMA0_RX0_DIDX + u64::from(ring) * 16, 0);
            }
        }
        if mask & 1 != 0 {
            self.wfdma_rx_didx = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WFDMA0_RST_DRX_PTR, WFDMA0_RST_DTX_PTR};

    #[test]
    fn reset_strobes_clear_selected_indices_without_reprogramming_rings() {
        let mut board = Mt7981Board::new();
        board.wfdma_tx_didx = [81, 16, 4, 5, 159];
        board.wfdma_tx_base = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000];
        board.wfdma_tx_count = [128, 256, 256, 256, 256];
        board.wfdma_rx_didx = 276;
        board.control_regs.insert(WFDMA0_RX0_DIDX, 276);
        board.control_regs.insert(WFDMA0_RX0_DIDX + 16, 77);
        board.mmio_write(WFDMA0_RST_DTX_PTR, (1 << 16) | (1 << 17));
        assert_eq!(board.wfdma_tx_didx, [0, 0, 4, 5, 159]);
        assert_eq!(board.wfdma_tx_base[1], 0x2000);
        assert_eq!(board.wfdma_tx_count[1], 256);
        board.mmio_write(WFDMA0_RST_DRX_PTR, 1);
        assert_eq!(board.wfdma_rx_didx, 0);
        assert_eq!(board.mmio_read(WFDMA0_RX0_DIDX), 0);
        assert_eq!(board.mmio_read(WFDMA0_RX0_DIDX + 16), 77);
        assert_eq!(board.mmio_read(WFDMA0_RST_DTX_PTR), 0);
        assert_eq!(board.mmio_read(WFDMA0_RST_DRX_PTR), 0);
    }

    #[test]
    fn active_low_logic_reset_clears_indices_and_pending_interrupts() {
        use crate::{WFDMA0_INT_SOURCE, WFDMA0_MCU_CMD_SOURCE, WFDMA0_RESET};
        let mut board = Mt7981Board::new();
        assert_eq!(board.mmio_read(WFDMA0_RESET), 0x30);
        board.wfdma_tx_didx = [7; 5];
        board.wfdma_rx_didx = 9;
        board.control_regs.insert(WFDMA0_INT_SOURCE, 0xffff);
        board.control_regs.insert(WFDMA0_MCU_CMD_SOURCE, 1);
        board.mmio_write(WFDMA0_RESET, 0x20);
        assert_eq!(board.wfdma_tx_didx, [0; 5]);
        assert_eq!(board.wfdma_rx_didx, 0);
        assert_eq!(board.mmio_read(WFDMA0_INT_SOURCE), 0);
        assert_eq!(board.mmio_read(WFDMA0_MCU_CMD_SOURCE), 0);
        board.wfdma_tx_didx[1] = 3;
        board.mmio_write(WFDMA0_RESET, 0x30);
        assert_eq!(board.wfdma_tx_didx[1], 3);
    }

    #[test]
    fn zero_reset_mask_preserves_indices() {
        let mut board = Mt7981Board::new();
        board.wfdma_tx_didx = [1; 5];
        board.wfdma_rx_didx = 9;
        board.mmio_write(WFDMA0_RST_DTX_PTR, 0);
        board.mmio_write(WFDMA0_RST_DRX_PTR, 0);
        assert_eq!(board.wfdma_tx_didx, [1; 5]);
        assert_eq!(board.wfdma_rx_didx, 9);
    }
}
