/*
 * Atheros AR2315 SPI Flash Memory support header file.
 *
 * Copyright (c) 2005, Atheros Communications Inc.
 * Copyright (C) 2006 FON Technology, SL.
 * Copyright (C) 2006 Imre Kaloz <kaloz@openwrt.org>
 * Copyright (C) 2006-2009 Felix Fietkau <nbd@openwrt.org>
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef __AR2315_SPIFLASH_H
#define __AR2315_SPIFLASH_H

#define STM_PAGE_SIZE           256

#define SFI_WRITE_BUFFER_SIZE   4
#define SFI_FLASH_ADDR_MASK     0x00ffffff

#define STM_8MBIT_SIGNATURE     0x13
#define STM_M25P80_BYTE_COUNT   1048576
#define STM_M25P80_SECTOR_COUNT 16
#define STM_M25P80_SECTOR_SIZE  0x10000

#define STM_16MBIT_SIGNATURE    0x14
#define STM_M25P16_BYTE_COUNT   2097152
#define STM_M25P16_SECTOR_COUNT 32
#define STM_M25P16_SECTOR_SIZE  0x10000

#define STM_32MBIT_SIGNATURE    0x15
#define STM_M25P32_BYTE_COUNT   4194304
#define STM_M25P32_SECTOR_COUNT 64
#define STM_M25P32_SECTOR_SIZE  0x10000

#define STM_64MBIT_SIGNATURE    0x16
#define STM_M25P64_BYTE_COUNT   8388608
#define STM_M25P64_SECTOR_COUNT 128
#define STM_M25P64_SECTOR_SIZE  0x10000

#define STM_128MBIT_SIGNATURE   0x17
#define STM_M25P128_BYTE_COUNT   16777216
#define STM_M25P128_SECTOR_COUNT 256
#define STM_M25P128_SECTOR_SIZE  0x10000

#define STM_1MB_BYTE_COUNT   STM_M25P80_BYTE_COUNT
#define STM_1MB_SECTOR_COUNT STM_M25P80_SECTOR_COUNT
#define STM_1MB_SECTOR_SIZE  STM_M25P80_SECTOR_SIZE
#define STM_2MB_BYTE_COUNT   STM_M25P16_BYTE_COUNT
#define STM_2MB_SECTOR_COUNT STM_M25P16_SECTOR_COUNT
#define STM_2MB_SECTOR_SIZE  STM_M25P16_SECTOR_SIZE
#define STM_4MB_BYTE_COUNT   STM_M25P32_BYTE_COUNT
#define STM_4MB_SECTOR_COUNT STM_M25P32_SECTOR_COUNT
#define STM_4MB_SECTOR_SIZE  STM_M25P32_SECTOR_SIZE
#define STM_8MB_BYTE_COUNT   STM_M25P64_BYTE_COUNT
#define STM_8MB_SECTOR_COUNT STM_M25P64_SECTOR_COUNT
#define STM_8MB_SECTOR_SIZE  STM_M25P64_SECTOR_SIZE
#define STM_16MB_BYTE_COUNT   STM_M25P128_BYTE_COUNT
#define STM_16MB_SECTOR_COUNT STM_M25P128_SECTOR_COUNT
#define STM_16MB_SECTOR_SIZE  STM_M25P128_SECTOR_SIZE

/*
 * ST Microelectronics Opcodes for Serial Flash
 */

#define STM_OP_WR_ENABLE       0x06     /* Write Enable */
#define STM_OP_WR_DISABLE      0x04     /* Write Disable */
#define STM_OP_RD_STATUS       0x05     /* Read Status */
#define STM_OP_WR_STATUS       0x01     /* Write Status */
#define STM_OP_RD_DATA         0x03     /* Read Data */
#define STM_OP_FAST_RD_DATA    0x0b     /* Fast Read Data */
#define STM_OP_PAGE_PGRM       0x02     /* Page Program */
#define STM_OP_SECTOR_ERASE    0xd8     /* Sector Erase */
#define STM_OP_BULK_ERASE      0xc7     /* Bulk Erase */
#define STM_OP_DEEP_PWRDOWN    0xb9     /* Deep Power-Down Mode */
#define STM_OP_RD_SIG          0xab     /* Read Electronic Signature */

#define STM_STATUS_WIP       0x01       /* Write-In-Progress */
#define STM_STATUS_WEL       0x02       /* Write Enable Latch */
#define STM_STATUS_BP0       0x04       /* Block Protect 0 */
#define STM_STATUS_BP1       0x08       /* Block Protect 1 */
#define STM_STATUS_BP2       0x10       /* Block Protect 2 */
#define STM_STATUS_SRWD      0x80       /* Status Register Write Disable */

/*
 * SPI Flash Interface Registers
 */

#define SPI_FLASH_CTL           0x00
#define SPI_FLASH_OPCODE        0x04
#define SPI_FLASH_DATA          0x08

#define SPI_CTL_START           0x00000100
#define SPI_CTL_BUSY            0x00010000
#define SPI_CTL_TXCNT_MASK      0x0000000f
#define SPI_CTL_RXCNT_MASK      0x000000f0
#define SPI_CTL_TX_RX_CNT_MASK  0x000000ff
#define SPI_CTL_SIZE_MASK       0x00060000

#define SPI_CTL_CLK_SEL_MASK    0x03000000
#define SPI_OPCODE_MASK         0x000000ff

#define SPI_STATUS_WIP		STM_STATUS_WIP

#endif
