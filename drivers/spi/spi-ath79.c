/*
 * SPI controller driver for the Atheros AR71XX/AR724X/AR913X SoCs
 *
 * Copyright (C) 2009-2011 Gabor Juhos <juhosg@openwrt.org>
 *
 * This driver has been based on the spi-gpio.c:
 *	Copyright (C) 2006,2008 David Brownell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/spi/spi.h>
#include <linux/spi/spi_bitbang.h>
#include <linux/bitops.h>
#include <linux/gpio.h>
#include <linux/clk.h>
#include <linux/err.h>

#include <asm/mach-ath79/ar71xx_regs.h>
#include <asm/mach-ath79/ath79_spi_platform.h>

#define DRV_NAME	"ath79-spi"

#define ATH79_SPI_RRW_DELAY_FACTOR	12000
#define MHZ				(1000 * 1000)

#define ATH79_SPI_CS_LINE_MAX		2

enum ath79_spi_state {
	ATH79_SPI_STATE_WAIT_CMD = 0,
	ATH79_SPI_STATE_WAIT_READ,
};

struct ath79_spi {
	struct spi_bitbang	bitbang;
	u32			ioc_base;
	u32			reg_ctrl;
	void __iomem		*base;
	struct clk		*clk;
	unsigned		rrw_delay;

	enum ath79_spi_state	state;
	u32			clk_div;
	unsigned long 		read_addr;
	unsigned long		ahb_rate;
};

static inline u32 ath79_spi_rr(struct ath79_spi *sp, unsigned reg)
{
	return ioread32(sp->base + reg);
}

static inline void ath79_spi_wr(struct ath79_spi *sp, unsigned reg, u32 val)
{
	iowrite32(val, sp->base + reg);
}

static inline struct ath79_spi *ath79_spidev_to_sp(struct spi_device *spi)
{
	return spi_master_get_devdata(spi->master);
}

static inline void ath79_spi_delay(struct ath79_spi *sp, unsigned nsecs)
{
	if (nsecs > sp->rrw_delay)
		ndelay(nsecs - sp->rrw_delay);
}

static void ath79_spi_chipselect(struct spi_device *spi, int is_active)
{
	struct ath79_spi *sp = ath79_spidev_to_sp(spi);
	int cs_high = (spi->mode & SPI_CS_HIGH) ? is_active : !is_active;
	struct ath79_spi_controller_data *cdata = spi->controller_data;

	if (is_active) {
		/* set initial clock polarity */
		if (spi->mode & SPI_CPOL)
			sp->ioc_base |= AR71XX_SPI_IOC_CLK;
		else
			sp->ioc_base &= ~AR71XX_SPI_IOC_CLK;

		ath79_spi_wr(sp, AR71XX_SPI_REG_IOC, sp->ioc_base);
	}

	switch (cdata->cs_type) {
	case ATH79_SPI_CS_TYPE_INTERNAL:
		if (cs_high)
			sp->ioc_base |= AR71XX_SPI_IOC_CS(cdata->cs_line);
		else
			sp->ioc_base &= ~AR71XX_SPI_IOC_CS(cdata->cs_line);

		ath79_spi_wr(sp, AR71XX_SPI_REG_IOC, sp->ioc_base);
		break;

	case ATH79_SPI_CS_TYPE_GPIO:
		/* SPI is normally active-low */
		if (gpio_cansleep(cdata->cs_line))
			gpio_set_value_cansleep(cdata->cs_line, cs_high);
		else
			gpio_set_value(cdata->cs_line, cs_high);
		break;
	}
}

static void ath79_spi_enable(struct ath79_spi *sp)
{
	/* enable GPIO mode */
	ath79_spi_wr(sp, AR71XX_SPI_REG_FS, AR71XX_SPI_FS_GPIO);

	/* save CTRL register */
	sp->reg_ctrl = ath79_spi_rr(sp, AR71XX_SPI_REG_CTRL);
	sp->ioc_base = ath79_spi_rr(sp, AR71XX_SPI_REG_IOC);
}

static void ath79_spi_disable(struct ath79_spi *sp)
{
	/* restore CTRL register */
	ath79_spi_wr(sp, AR71XX_SPI_REG_CTRL, sp->reg_ctrl);
	/* disable GPIO mode */
	ath79_spi_wr(sp, AR71XX_SPI_REG_FS, 0);
}

static int ath79_spi_setup_cs(struct spi_device *spi)
{
	struct ath79_spi_controller_data *cdata;
	unsigned long flags;
	int status;

	cdata = spi->controller_data;
	if (!cdata)
		return -EINVAL;

	status = 0;
	switch (cdata->cs_type) {
	case ATH79_SPI_CS_TYPE_INTERNAL:
		if (cdata->cs_line > ATH79_SPI_CS_LINE_MAX)
			status = -EINVAL;
		break;

	case ATH79_SPI_CS_TYPE_GPIO:
		flags = GPIOF_DIR_OUT;
		if (spi->mode & SPI_CS_HIGH)
			flags |= GPIOF_INIT_LOW;
		else
			flags |= GPIOF_INIT_HIGH;

		status = gpio_request_one(cdata->cs_line, flags,
					  dev_name(&spi->dev));
		break;
	}

	return status;
}

static void ath79_spi_cleanup_cs(struct spi_device *spi)
{
	struct ath79_spi_controller_data *cdata;

	cdata = spi->controller_data;
	if (!cdata)
		return;

	switch (cdata->cs_type) {
	case ATH79_SPI_CS_TYPE_INTERNAL:
		/* nothing to do */
		break;
	case ATH79_SPI_CS_TYPE_GPIO:
		gpio_free(cdata->cs_line);
		break;
	}
}

static int ath79_spi_setup(struct spi_device *spi)
{
	int status = 0;

	if (!spi->controller_state) {
		status = ath79_spi_setup_cs(spi);
		if (status)
			return status;
	}

	status = spi_bitbang_setup(spi);
	if (status && !spi->controller_state)
		ath79_spi_cleanup_cs(spi);

	return status;
}

static void ath79_spi_cleanup(struct spi_device *spi)
{
	ath79_spi_cleanup_cs(spi);
	spi_bitbang_cleanup(spi);
}

static u32 ath79_spi_txrx_mode0(struct spi_device *spi, unsigned nsecs,
			       u32 word, u8 bits)
{
	struct ath79_spi *sp = ath79_spidev_to_sp(spi);
	u32 ioc = sp->ioc_base;

	/* clock starts at inactive polarity */
	for (word <<= (32 - bits); likely(bits); bits--) {
		u32 out;

		if (word & (1 << 31))
			out = ioc | AR71XX_SPI_IOC_DO;
		else
			out = ioc & ~AR71XX_SPI_IOC_DO;

		/* setup MSB (to slave) on trailing edge */
		ath79_spi_wr(sp, AR71XX_SPI_REG_IOC, out);
		ath79_spi_delay(sp, nsecs);
		ath79_spi_wr(sp, AR71XX_SPI_REG_IOC, out | AR71XX_SPI_IOC_CLK);
		ath79_spi_delay(sp, nsecs);
		if (bits == 1)
			ath79_spi_wr(sp, AR71XX_SPI_REG_IOC, out);

		word <<= 1;
	}

	return ath79_spi_rr(sp, AR71XX_SPI_REG_RDS);
}

static int ath79_spi_do_read_flash_data(struct spi_device *spi,
					struct spi_transfer *t)
{
	struct ath79_spi *sp = ath79_spidev_to_sp(spi);

	/* disable GPIO mode */
	ath79_spi_wr(sp, AR71XX_SPI_REG_FS, 0);

	memcpy_fromio(t->rx_buf, sp->base + sp->read_addr, t->len);

	/* enable GPIO mode */
	ath79_spi_wr(sp, AR71XX_SPI_REG_FS, AR71XX_SPI_FS_GPIO);

	/* restore IOC register */
	ath79_spi_wr(sp, AR71XX_SPI_REG_IOC, sp->ioc_base);

	return t->len;
}

static int ath79_spi_do_read_flash_cmd(struct spi_device *spi,
				       struct spi_transfer *t)
{
	struct ath79_spi *sp = ath79_spidev_to_sp(spi);
	int len;
	const u8 *p;

	sp->read_addr = 0;

	len = t->len - 1;

	if (t->dummy)
		len -= 1;

	p = t->tx_buf;

	while (len--) {
		p++;
		sp->read_addr <<= 8;
		sp->read_addr |= *p;
	}

	return t->len;
}

static bool ath79_spi_is_read_cmd(struct spi_device *spi,
				 struct spi_transfer *t)
{
	return t->type == SPI_TRANSFER_FLASH_READ_CMD;
}

static bool ath79_spi_is_data_read(struct spi_device *spi,
				  struct spi_transfer *t)
{
	return t->type == SPI_TRANSFER_FLASH_READ_DATA;
}

static int ath79_spi_txrx_bufs(struct spi_device *spi, struct spi_transfer *t)
{
	struct ath79_spi *sp = ath79_spidev_to_sp(spi);
	int ret;

	switch (sp->state) {
	case ATH79_SPI_STATE_WAIT_CMD:
		if (ath79_spi_is_read_cmd(spi, t)) {
			ret = ath79_spi_do_read_flash_cmd(spi, t);
			sp->state = ATH79_SPI_STATE_WAIT_READ;
		} else {
			ret = spi_bitbang_bufs(spi, t);
		}
		break;

	case ATH79_SPI_STATE_WAIT_READ:
		if (ath79_spi_is_data_read(spi, t)) {
			ret = ath79_spi_do_read_flash_data(spi, t);
		} else {
			dev_warn(&spi->dev, "flash data read expected\n");
			ret = -EIO;
		}
		sp->state = ATH79_SPI_STATE_WAIT_CMD;
		break;

	default:
		BUG();
	}

	return ret;
}

static int ath79_spi_setup_transfer(struct spi_device *spi,
				    struct spi_transfer *t)
{
	struct ath79_spi *sp = ath79_spidev_to_sp(spi);
	struct ath79_spi_controller_data *cdata;
	int ret;

	ret = spi_bitbang_setup_transfer(spi, t);
	if (ret)
		return ret;

	cdata = spi->controller_data;
	if (cdata->is_flash)
		sp->bitbang.txrx_bufs = ath79_spi_txrx_bufs;
	else
		sp->bitbang.txrx_bufs = spi_bitbang_bufs;

	return ret;
}

static int ath79_spi_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct ath79_spi *sp;
	struct ath79_spi_platform_data *pdata;
	struct resource	*r;
	unsigned long rate;
	int ret;

	pdata = pdev->dev.platform_data;
	if (!pdata)
		return -EINVAL;

	master = spi_alloc_master(&pdev->dev, sizeof(*sp));
	if (master == NULL) {
		dev_err(&pdev->dev, "failed to allocate spi master\n");
		return -ENOMEM;
	}

	sp = spi_master_get_devdata(master);
	platform_set_drvdata(pdev, sp);

	sp->state = ATH79_SPI_STATE_WAIT_CMD;

	master->bits_per_word_mask = SPI_BPW_RANGE_MASK(1, 32);
	master->setup = ath79_spi_setup;
	master->cleanup = ath79_spi_cleanup;
	master->bus_num = pdata->bus_num;
	master->num_chipselect = pdata->num_chipselect;

	sp->bitbang.master = master;
	sp->bitbang.chipselect = ath79_spi_chipselect;
	sp->bitbang.txrx_word[SPI_MODE_0] = ath79_spi_txrx_mode0;
	sp->bitbang.setup_transfer = ath79_spi_setup_transfer;
	sp->bitbang.flags = SPI_CS_HIGH;

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (r == NULL) {
		ret = -ENOENT;
		goto err_put_master;
	}

	sp->base = devm_ioremap(&pdev->dev, r->start, resource_size(r));
	if (!sp->base) {
		ret = -ENXIO;
		goto err_put_master;
	}

	sp->clk = devm_clk_get(&pdev->dev, "ahb");
	if (IS_ERR(sp->clk)) {
		ret = PTR_ERR(sp->clk);
		goto err_put_master;
	}

	ret = clk_enable(sp->clk);
	if (ret)
		goto err_put_master;

	sp->ahb_rate = clk_get_rate(sp->clk);
	rate = DIV_ROUND_UP(sp->ahb_rate, MHZ);
	if (!rate) {
		ret = -EINVAL;
		goto err_clk_disable;
	}

	sp->rrw_delay = ATH79_SPI_RRW_DELAY_FACTOR / rate;
	dev_dbg(&pdev->dev, "register read/write delay is %u nsecs\n",
		sp->rrw_delay);

	ath79_spi_enable(sp);
	ret = spi_bitbang_start(&sp->bitbang);
	if (ret)
		goto err_disable;

	return 0;

err_disable:
	ath79_spi_disable(sp);
err_clk_disable:
	clk_disable(sp->clk);
err_put_master:
	spi_master_put(sp->bitbang.master);

	return ret;
}

static int ath79_spi_remove(struct platform_device *pdev)
{
	struct ath79_spi *sp = platform_get_drvdata(pdev);

	spi_bitbang_stop(&sp->bitbang);
	ath79_spi_disable(sp);
	clk_disable(sp->clk);
	spi_master_put(sp->bitbang.master);

	return 0;
}

static void ath79_spi_shutdown(struct platform_device *pdev)
{
	ath79_spi_remove(pdev);
}

static struct platform_driver ath79_spi_driver = {
	.probe		= ath79_spi_probe,
	.remove		= ath79_spi_remove,
	.shutdown	= ath79_spi_shutdown,
	.driver		= {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
	},
};
module_platform_driver(ath79_spi_driver);

MODULE_DESCRIPTION("SPI controller driver for Atheros AR71XX/AR724X/AR913X");
MODULE_AUTHOR("Gabor Juhos <juhosg@openwrt.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRV_NAME);
