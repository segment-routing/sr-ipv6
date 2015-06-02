
/*
 * MTD driver for the SPI Flash Memory support on Atheros AR2315
 *
 * Copyright (c) 2005-2006 Atheros Communications Inc.
 * Copyright (C) 2006-2007 FON Technology, SL.
 * Copyright (C) 2006-2007 Imre Kaloz <kaloz@openwrt.org>
 * Copyright (C) 2006-2009 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2012 Alexandros C. Couloumbis <alex@ozo.com>
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/mutex.h>

#include "ar2315_spiflash.h"

#define DRIVER_NAME "ar2315-spiflash"

#define busy_wait(_priv, _condition, _wait) do { \
	while (_condition) { \
		if (_wait > 1) \
			msleep(_wait); \
		else if ((_wait == 1) && need_resched()) \
			schedule(); \
		else \
			udelay(1); \
	} \
} while (0)

enum {
	FLASH_NONE,
	FLASH_1MB,
	FLASH_2MB,
	FLASH_4MB,
	FLASH_8MB,
	FLASH_16MB,
};

/* Flash configuration table */
struct flashconfig {
	u32 byte_cnt;
	u32 sector_cnt;
	u32 sector_size;
};

static const struct flashconfig flashconfig_tbl[] = {
	[FLASH_NONE] = { 0, 0, 0},
	[FLASH_1MB]  = { STM_1MB_BYTE_COUNT, STM_1MB_SECTOR_COUNT,
			 STM_1MB_SECTOR_SIZE},
	[FLASH_2MB]  = { STM_2MB_BYTE_COUNT, STM_2MB_SECTOR_COUNT,
			 STM_2MB_SECTOR_SIZE},
	[FLASH_4MB]  = { STM_4MB_BYTE_COUNT, STM_4MB_SECTOR_COUNT,
			 STM_4MB_SECTOR_SIZE},
	[FLASH_8MB]  = { STM_8MB_BYTE_COUNT, STM_8MB_SECTOR_COUNT,
			 STM_8MB_SECTOR_SIZE},
	[FLASH_16MB] = { STM_16MB_BYTE_COUNT, STM_16MB_SECTOR_COUNT,
			 STM_16MB_SECTOR_SIZE}
};

/* Mapping of generic opcodes to STM serial flash opcodes */
enum {
	SPI_WRITE_ENABLE,
	SPI_WRITE_DISABLE,
	SPI_RD_STATUS,
	SPI_WR_STATUS,
	SPI_RD_DATA,
	SPI_FAST_RD_DATA,
	SPI_PAGE_PROGRAM,
	SPI_SECTOR_ERASE,
	SPI_BULK_ERASE,
	SPI_DEEP_PWRDOWN,
	SPI_RD_SIG,
};

struct opcodes {
	__u16 code;
	__s8 tx_cnt;
	__s8 rx_cnt;
};

static const struct opcodes stm_opcodes[] = {
	[SPI_WRITE_ENABLE] = {STM_OP_WR_ENABLE, 1, 0},
	[SPI_WRITE_DISABLE] = {STM_OP_WR_DISABLE, 1, 0},
	[SPI_RD_STATUS] = {STM_OP_RD_STATUS, 1, 1},
	[SPI_WR_STATUS] = {STM_OP_WR_STATUS, 1, 0},
	[SPI_RD_DATA] = {STM_OP_RD_DATA, 4, 4},
	[SPI_FAST_RD_DATA] = {STM_OP_FAST_RD_DATA, 5, 0},
	[SPI_PAGE_PROGRAM] = {STM_OP_PAGE_PGRM, 8, 0},
	[SPI_SECTOR_ERASE] = {STM_OP_SECTOR_ERASE, 4, 0},
	[SPI_BULK_ERASE] = {STM_OP_BULK_ERASE, 1, 0},
	[SPI_DEEP_PWRDOWN] = {STM_OP_DEEP_PWRDOWN, 1, 0},
	[SPI_RD_SIG] = {STM_OP_RD_SIG, 4, 1},
};

/* Driver private data structure */
struct spiflash_priv {
	struct mtd_info mtd;
	void __iomem *readaddr; /* memory mapped data for read  */
	void __iomem *mmraddr;  /* memory mapped register space */
	struct mutex lock;	/* serialize registers access */
};

#define to_spiflash(_mtd) container_of(_mtd, struct spiflash_priv, mtd)

enum {
	FL_READY,
	FL_READING,
	FL_ERASING,
	FL_WRITING
};

/*****************************************************************************/

static u32
spiflash_read_reg(struct spiflash_priv *priv, int reg)
{
	return ioread32(priv->mmraddr + reg);
}

static void
spiflash_write_reg(struct spiflash_priv *priv, int reg, u32 data)
{
	iowrite32(data, priv->mmraddr + reg);
}

static u32
spiflash_wait_busy(struct spiflash_priv *priv)
{
	u32 reg;

	busy_wait(priv, (reg = spiflash_read_reg(priv, SPI_FLASH_CTL)) &
		SPI_CTL_BUSY, 0);
	return reg;
}

static u32
spiflash_sendcmd(struct spiflash_priv *priv, int opcode, u32 addr)
{
	const struct opcodes *op;
	u32 reg, mask;

	op = &stm_opcodes[opcode];
	reg = spiflash_wait_busy(priv);
	spiflash_write_reg(priv, SPI_FLASH_OPCODE,
			   ((u32)op->code) | (addr << 8));

	reg &= ~SPI_CTL_TX_RX_CNT_MASK;
	reg |= SPI_CTL_START | op->tx_cnt | (op->rx_cnt << 4);

	spiflash_write_reg(priv, SPI_FLASH_CTL, reg);
	spiflash_wait_busy(priv);

	if (!op->rx_cnt)
		return 0;

	reg = spiflash_read_reg(priv, SPI_FLASH_DATA);

	switch (op->rx_cnt) {
	case 1:
		mask = 0x000000ff;
		break;
	case 2:
		mask = 0x0000ffff;
		break;
	case 3:
		mask = 0x00ffffff;
		break;
	default:
		mask = 0xffffffff;
		break;
	}
	reg &= mask;

	return reg;
}

/*
 * Probe SPI flash device
 * Function returns 0 for failure.
 * and flashconfig_tbl array index for success.
 */
static int
spiflash_probe_chip(struct platform_device *pdev, struct spiflash_priv *priv)
{
	u32 sig = spiflash_sendcmd(priv, SPI_RD_SIG, 0);
	int flash_size;

	switch (sig) {
	case STM_8MBIT_SIGNATURE:
		flash_size = FLASH_1MB;
		break;
	case STM_16MBIT_SIGNATURE:
		flash_size = FLASH_2MB;
		break;
	case STM_32MBIT_SIGNATURE:
		flash_size = FLASH_4MB;
		break;
	case STM_64MBIT_SIGNATURE:
		flash_size = FLASH_8MB;
		break;
	case STM_128MBIT_SIGNATURE:
		flash_size = FLASH_16MB;
		break;
	default:
		dev_warn(&pdev->dev, "read of flash device signature failed!\n");
		return 0;
	}

	return flash_size;
}

static void
spiflash_wait_complete(struct spiflash_priv *priv, unsigned int timeout)
{
	busy_wait(priv, spiflash_sendcmd(priv, SPI_RD_STATUS, 0) &
		SPI_STATUS_WIP, timeout);
}

static int
spiflash_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct spiflash_priv *priv = to_spiflash(mtd);
	const struct opcodes *op;
	u32 temp, reg;

	if (instr->addr + instr->len > mtd->size)
		return -EINVAL;

	mutex_lock(&priv->lock);

	spiflash_sendcmd(priv, SPI_WRITE_ENABLE, 0);
	reg = spiflash_wait_busy(priv);

	op = &stm_opcodes[SPI_SECTOR_ERASE];
	temp = ((u32)instr->addr << 8) | (u32)(op->code);
	spiflash_write_reg(priv, SPI_FLASH_OPCODE, temp);

	reg &= ~SPI_CTL_TX_RX_CNT_MASK;
	reg |= op->tx_cnt | SPI_CTL_START;
	spiflash_write_reg(priv, SPI_FLASH_CTL, reg);

	spiflash_wait_complete(priv, 20);

	mutex_unlock(&priv->lock);

	instr->state = MTD_ERASE_DONE;
	mtd_erase_callback(instr);

	return 0;
}

static int
spiflash_read(struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen,
	      u_char *buf)
{
	struct spiflash_priv *priv = to_spiflash(mtd);

	if (!len)
		return 0;

	if (from + len > mtd->size)
		return -EINVAL;

	*retlen = len;

	mutex_lock(&priv->lock);

	memcpy_fromio(buf, priv->readaddr + from, len);

	mutex_unlock(&priv->lock);

	return 0;
}

static int
spiflash_write(struct mtd_info *mtd, loff_t to, size_t len, size_t *retlen,
	       const u8 *buf)
{
	struct spiflash_priv *priv = to_spiflash(mtd);
	u32 opcode, bytes_left;

	*retlen = 0;

	if (!len)
		return 0;

	if (to + len > mtd->size)
		return -EINVAL;

	bytes_left = len;

	do {
		u32 read_len, reg, page_offset, spi_data = 0;

		read_len = min(bytes_left, sizeof(u32));

		/* 32-bit writes cannot span across a page boundary
		 * (256 bytes). This types of writes require two page
		 * program operations to handle it correctly. The STM part
		 * will write the overflow data to the beginning of the
		 * current page as opposed to the subsequent page.
		 */
		page_offset = (to & (STM_PAGE_SIZE - 1)) + read_len;

		if (page_offset > STM_PAGE_SIZE)
			read_len -= (page_offset - STM_PAGE_SIZE);

		mutex_lock(&priv->lock);

		spiflash_sendcmd(priv, SPI_WRITE_ENABLE, 0);
		spi_data = 0;
		switch (read_len) {
		case 4:
			spi_data |= buf[3] << 24;
			/* fall through */
		case 3:
			spi_data |= buf[2] << 16;
			/* fall through */
		case 2:
			spi_data |= buf[1] << 8;
			/* fall through */
		case 1:
			spi_data |= buf[0] & 0xff;
			break;
		default:
			break;
		}

		spiflash_write_reg(priv, SPI_FLASH_DATA, spi_data);
		opcode = stm_opcodes[SPI_PAGE_PROGRAM].code |
			(to & 0x00ffffff) << 8;
		spiflash_write_reg(priv, SPI_FLASH_OPCODE, opcode);

		reg = spiflash_read_reg(priv, SPI_FLASH_CTL);
		reg &= ~SPI_CTL_TX_RX_CNT_MASK;
		reg |= (read_len + 4) | SPI_CTL_START;
		spiflash_write_reg(priv, SPI_FLASH_CTL, reg);

		spiflash_wait_complete(priv, 1);

		mutex_unlock(&priv->lock);

		bytes_left -= read_len;
		to += read_len;
		buf += read_len;

		*retlen += read_len;
	} while (bytes_left != 0);

	return 0;
}

#if defined CONFIG_MTD_REDBOOT_PARTS || CONFIG_MTD_MYLOADER_PARTS
static const char * const part_probe_types[] = {
	"cmdlinepart", "RedBoot", "MyLoader", NULL
};
#endif

static int
spiflash_probe(struct platform_device *pdev)
{
	struct spiflash_priv *priv;
	struct mtd_info *mtd;
	struct resource *res;
	int index;
	int result = 0;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	mutex_init(&priv->lock);
	mtd = &priv->mtd;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	priv->mmraddr = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(priv->mmraddr)) {
		dev_warn(&pdev->dev, "failed to map flash MMR\n");
		return PTR_ERR(priv->mmraddr);
	}

	index = spiflash_probe_chip(pdev, priv);
	if (!index) {
		dev_warn(&pdev->dev, "found no flash device\n");
		return -ENODEV;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	priv->readaddr = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(priv->readaddr)) {
		dev_warn(&pdev->dev, "failed to map flash read mem\n");
		return PTR_ERR(priv->readaddr);
	}

	platform_set_drvdata(pdev, priv);
	mtd->name = "spiflash";
	mtd->type = MTD_NORFLASH;
	mtd->flags = (MTD_CAP_NORFLASH|MTD_WRITEABLE);
	mtd->size = flashconfig_tbl[index].byte_cnt;
	mtd->erasesize = flashconfig_tbl[index].sector_size;
	mtd->writesize = 1;
	mtd->numeraseregions = 0;
	mtd->eraseregions = NULL;
	mtd->_erase = spiflash_erase;
	mtd->_read = spiflash_read;
	mtd->_write = spiflash_write;
	mtd->owner = THIS_MODULE;

	dev_info(&pdev->dev, "%lld Kbytes flash detected\n", mtd->size >> 10);

#if defined CONFIG_MTD_REDBOOT_PARTS || CONFIG_MTD_MYLOADER_PARTS
	/* parse redboot partitions */

	result = mtd_device_parse_register(mtd, part_probe_types,
					   NULL, NULL, 0);
#endif

	return result;
}

static int
spiflash_remove(struct platform_device *pdev)
{
	struct spiflash_priv *priv = platform_get_drvdata(pdev);

	mtd_device_unregister(&priv->mtd);

	return 0;
}

static struct platform_driver spiflash_driver = {
	.driver.name = DRIVER_NAME,
	.probe = spiflash_probe,
	.remove = spiflash_remove,
};

module_platform_driver(spiflash_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenWrt.org");
MODULE_AUTHOR("Atheros Communications Inc");
MODULE_DESCRIPTION("MTD driver for SPI Flash on Atheros AR2315+ SOC");
MODULE_ALIAS("platform:" DRIVER_NAME);

