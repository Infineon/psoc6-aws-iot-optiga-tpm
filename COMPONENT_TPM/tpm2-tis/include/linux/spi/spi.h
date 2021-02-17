/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2005 David Brownell
 */

#ifndef __LINUX_SPI_H
#define __LINUX_SPI_H

#include <linux/device.h>

/**
 * struct spi_delay - SPI delay information
 * @value: Value for the delay
 * @unit: Unit for the delay
 */
struct spi_delay {
#define SPI_DELAY_UNIT_USECS    0
#define SPI_DELAY_UNIT_NSECS    1
#define SPI_DELAY_UNIT_SCK    2
    unsigned short    value;
    unsigned char    unit;
};

/**
 * struct spi_device - Controller side proxy for an SPI slave device
 * @dev: Driver model representation of the device.
 * @controller: SPI controller used with the device.
 * @master: Copy of controller, for backwards compatibility.
 * @max_speed_hz: Maximum clock rate to be used with this chip
 *    (on this board); may be changed by the device's driver.
 *    The spi_transfer.speed_hz can override this for each transfer.
 * @chip_select: Chipselect, distinguishing chips handled by @controller.
 * @mode: The spi mode defines how data is clocked out and in.
 *    This may be changed by the device's driver.
 *    The "active low" default for chipselect mode can be overridden
 *    (by specifying SPI_CS_HIGH) as can the "MSB first" default for
 *    each word in a transfer (by specifying SPI_LSB_FIRST).
 * @bits_per_word: Data transfers involve one or more words; word sizes
 *    like eight or 12 bits are common.  In-memory wordsizes are
 *    powers of two bytes (e.g. 20 bit samples use 32 bits).
 *    This may be changed by the device's driver, or left at the
 *    default (0) indicating protocol words are eight bit bytes.
 *    The spi_transfer.bits_per_word can override this for each transfer.
 * @rt: Make the pump thread real time priority.
 * @irq: Negative, or the number passed to request_irq() to receive
 *    interrupts from this device.
 * @controller_state: Controller's runtime state
 * @controller_data: Board-specific definitions for controller, such as
 *    FIFO initialization parameters; from board_info.controller_data
 * @modalias: Name of the driver to use with this device, or an alias
 *    for that name.  This appears in the sysfs "modalias" attribute
 *    for driver coldplugging, and in uevents used for hotplugging
 * @driver_override: If the name of a driver is written to this attribute, then
 *    the device will bind to the named driver and only the named driver.
 * @cs_gpio: LEGACY: gpio number of the chipselect line (optional, -ENOENT when
 *    not using a GPIO line) use cs_gpiod in new drivers by opting in on
 *    the spi_master.
 * @cs_gpiod: gpio descriptor of the chipselect line (optional, NULL when
 *    not using a GPIO line)
 * @word_delay: delay to be inserted between consecutive
 *    words of a transfer
 *
 * @statistics: statistics for the spi_device
 *
 * A @spi_device is used to interchange data between an SPI slave
 * (usually a discrete chip) and CPU memory.
 *
 * In @dev, the platform_data is used to hold information about this
 * device that's meaningful to the device's protocol driver, but not
 * to its controller.  One example might be an identifier for a chip
 * variant with slightly different functionality; another might be
 * information about how this particular board wires the chip's pins.
 */
struct spi_device {
    struct device        dev;
    void                 *controller;
};

static inline void *spi_get_drvdata(struct spi_device *spi)
{
    return dev_get_drvdata(&spi->dev);
}

/*---------------------------------------------------------------------------*/

/*
 * I/O INTERFACE between SPI controller and protocol drivers
 *
 * Protocol drivers use a queue of spi_messages, each transferring data
 * between the controller and memory buffers.
 *
 * The spi_messages themselves consist of a series of read+write transfer
 * segments.  Those segments always read the same number of bits as they
 * write; but one or the other is easily ignored by passing a null buffer
 * pointer.  (This is unlike most types of I/O API, because SPI hardware
 * is full duplex.)
 *
 * NOTE:  Allocation of spi_transfer and spi_message memory is entirely
 * up to the protocol driver, which guarantees the integrity of both (as
 * well as the data buffers) for as long as the message is queued.
 */

/**
 * struct spi_transfer - a read/write buffer pair
 * @tx_buf: data to be written (dma-safe memory), or NULL
 * @rx_buf: data to be read (dma-safe memory), or NULL
 * @tx_dma: DMA address of tx_buf, if @spi_message.is_dma_mapped
 * @rx_dma: DMA address of rx_buf, if @spi_message.is_dma_mapped
 * @tx_nbits: number of bits used for writing. If 0 the default
 *      (SPI_NBITS_SINGLE) is used.
 * @rx_nbits: number of bits used for reading. If 0 the default
 *      (SPI_NBITS_SINGLE) is used.
 * @len: size of rx and tx buffers (in bytes)
 * @speed_hz: Select a speed other than the device default for this
 *      transfer. If 0 the default (from @spi_device) is used.
 * @bits_per_word: select a bits_per_word other than the device default
 *      for this transfer. If 0 the default (from @spi_device) is used.
 * @cs_change: affects chipselect after this transfer completes
 * @cs_change_delay: delay between cs deassert and assert when
 *      @cs_change is set and @spi_transfer is not the last in @spi_message
 * @delay: delay to be introduced after this transfer before
 *    (optionally) changing the chipselect status, then starting
 *    the next transfer or completing this @spi_message.
 * @delay_usecs: microseconds to delay after this transfer before
 *    (optionally) changing the chipselect status, then starting
 *    the next transfer or completing this @spi_message.
 * @word_delay: inter word delay to be introduced after each word size
 *    (set by bits_per_word) transmission.
 * @effective_speed_hz: the effective SCK-speed that was used to
 *      transfer this transfer. Set to 0 if the spi bus driver does
 *      not support it.
 * @transfer_list: transfers are sequenced through @spi_message.transfers
 * @tx_sg: Scatterlist for transmit, currently not for client use
 * @rx_sg: Scatterlist for receive, currently not for client use
 * @ptp_sts_word_pre: The word (subject to bits_per_word semantics) offset
 *    within @tx_buf for which the SPI device is requesting that the time
 *    snapshot for this transfer begins. Upon completing the SPI transfer,
 *    this value may have changed compared to what was requested, depending
 *    on the available snapshotting resolution (DMA transfer,
 *    @ptp_sts_supported is false, etc).
 * @ptp_sts_word_post: See @ptp_sts_word_post. The two can be equal (meaning
 *    that a single byte should be snapshotted).
 *    If the core takes care of the timestamp (if @ptp_sts_supported is false
 *    for this controller), it will set @ptp_sts_word_pre to 0, and
 *    @ptp_sts_word_post to the length of the transfer. This is done
 *    purposefully (instead of setting to spi_transfer->len - 1) to denote
 *    that a transfer-level snapshot taken from within the driver may still
 *    be of higher quality.
 * @ptp_sts: Pointer to a memory location held by the SPI slave device where a
 *    PTP system timestamp structure may lie. If drivers use PIO or their
 *    hardware has some sort of assist for retrieving exact transfer timing,
 *    they can (and should) assert @ptp_sts_supported and populate this
 *    structure using the ptp_read_system_*ts helper functions.
 *    The timestamp must represent the time at which the SPI slave device has
 *    processed the word, i.e. the "pre" timestamp should be taken before
 *    transmitting the "pre" word, and the "post" timestamp after receiving
 *    transmit confirmation from the controller for the "post" word.
 * @timestamped_pre: Set by the SPI controller driver to denote it has acted
 *    upon the @ptp_sts request. Not set when the SPI core has taken care of
 *    the task. SPI device drivers are free to print a warning if this comes
 *    back unset and they need the better resolution.
 * @timestamped_post: See above. The reason why both exist is that these
 *    booleans are also used to keep state in the core SPI logic.
 *
 * SPI transfers always write the same number of bytes as they read.
 * Protocol drivers should always provide @rx_buf and/or @tx_buf.
 * In some cases, they may also want to provide DMA addresses for
 * the data being transferred; that may reduce overhead, when the
 * underlying driver uses dma.
 *
 * If the transmit buffer is null, zeroes will be shifted out
 * while filling @rx_buf.  If the receive buffer is null, the data
 * shifted in will be discarded.  Only "len" bytes shift out (or in).
 * It's an error to try to shift out a partial word.  (For example, by
 * shifting out three bytes with word size of sixteen or twenty bits;
 * the former uses two bytes per word, the latter uses four bytes.)
 *
 * In-memory data values are always in native CPU byte order, translated
 * from the wire byte order (big-endian except with SPI_LSB_FIRST).  So
 * for example when bits_per_word is sixteen, buffers are 2N bytes long
 * (@len = 2N) and hold N sixteen bit words in CPU byte order.
 *
 * When the word size of the SPI transfer is not a power-of-two multiple
 * of eight bits, those in-memory words include extra bits.  In-memory
 * words are always seen by protocol drivers as right-justified, so the
 * undefined (rx) or unused (tx) bits are always the most significant bits.
 *
 * All SPI transfers start with the relevant chipselect active.  Normally
 * it stays selected until after the last transfer in a message.  Drivers
 * can affect the chipselect signal using cs_change.
 *
 * (i) If the transfer isn't the last one in the message, this flag is
 * used to make the chipselect briefly go inactive in the middle of the
 * message.  Toggling chipselect in this way may be needed to terminate
 * a chip command, letting a single spi_message perform all of group of
 * chip transactions together.
 *
 * (ii) When the transfer is the last one in the message, the chip may
 * stay selected until the next transfer.  On multi-device SPI busses
 * with nothing blocking messages going to other devices, this is just
 * a performance hint; starting a message to another device deselects
 * this one.  But in other cases, this can be used to ensure correctness.
 * Some devices need protocol transactions to be built from a series of
 * spi_message submissions, where the content of one message is determined
 * by the results of previous messages and where the whole transaction
 * ends when the chipselect goes intactive.
 *
 * When SPI can transfer in 1x,2x or 4x. It can get this transfer information
 * from device through @tx_nbits and @rx_nbits. In Bi-direction, these
 * two should both be set. User can set transfer mode with SPI_NBITS_SINGLE(1x)
 * SPI_NBITS_DUAL(2x) and SPI_NBITS_QUAD(4x) to support these three transfer.
 *
 * The code that submits an spi_message (and its spi_transfers)
 * to the lower layers is responsible for managing its memory.
 * Zero-initialize every field you don't set up explicitly, to
 * insulate against future API updates.  After you submit a message
 * and its transfers, ignore them until its completion callback.
 */
struct spi_transfer {
    /* it's ok if tx_buf == rx_buf (right?)
     * for MicroWire, one buffer must be null
     * buffers must work with dma_*map_single() calls, unless
     *   spi_message.is_dma_mapped reports a pre-existing mapping
     */
    const void    *tx_buf;
    void        *rx_buf;
    unsigned    len;

    unsigned    cs_change:1;

    struct spi_delay    delay;

};

#endif /* __LINUX_SPI_H */
