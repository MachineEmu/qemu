use std::collections::VecDeque;

use crate::*;

/// A minimal 16550-compatible UART state model.
#[derive(Debug, Default)]
pub struct Uart {
    rx: VecDeque<u8>,
    tx: Vec<u8>,
    ier: u8,
    fcr: u8,
    lcr: u8,
}

impl Uart {
    pub(crate) fn read(&mut self, offset: u64) -> u32 {
        match offset {
            UART_RBR_THR_DLL => self.rx.pop_front().map_or(0, u32::from),
            UART_IER_DLH => u32::from(self.ier),
            UART_IIR_FCR => 1,
            UART_LCR => u32::from(self.lcr),
            UART_LSR => {
                let mut status = UART_LSR_THR_EMPTY | UART_LSR_TRANSMITTER_EMPTY;
                if !self.rx.is_empty() {
                    status |= UART_LSR_DATA_READY;
                }
                status
            }
            _ => 0,
        }
    }

    pub(crate) fn write(&mut self, offset: u64, value: u32) {
        match offset {
            UART_RBR_THR_DLL => self.tx.push((value & 0xff) as u8),
            UART_IER_DLH => self.ier = (value & 0xff) as u8,
            UART_IIR_FCR => self.fcr = (value & 0xff) as u8,
            UART_LCR => self.lcr = (value & 0xff) as u8,
            _ => {}
        }
    }

    /// Queues bytes that the guest can read from the UART.
    pub fn push_rx(&mut self, bytes: &[u8]) {
        self.rx.extend(bytes.iter().copied());
    }

    /// Returns and clears bytes written by the guest.
    pub fn take_tx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.tx)
    }

    /// Removes one byte written by the guest, preserving FIFO order.
    pub fn take_tx_byte(&mut self) -> Option<u8> {
        if self.tx.is_empty() {
            None
        } else {
            Some(self.tx.remove(0))
        }
    }
}
