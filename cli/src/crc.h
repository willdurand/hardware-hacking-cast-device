/* SPDX-License-Identifier: GPL-2.0 */

/* Copyright (c) 2022 William Durand */
#ifndef CRC_H
#define CRC_H

#include <stdint.h>

uint32_t crc32(uint32_t crc, uint8_t* buf, uint64_t size);

#endif
