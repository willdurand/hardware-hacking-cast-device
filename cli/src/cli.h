/* SPDX-License-Identifier: GPL-2.0 */

/* Copyright (c) 2018 Rockchip Electronics Co. Ltd. */
/* Copyright (c) 2022 William Durand */
#ifndef CLI_H
#define CLI_H

#include <stdint.h>

enum partition_type
{
  PART_VENDOR = 1,
  PART_IDBLOCK = 2,
  PART_KERNEL = 4,
  PART_BOOT = 8,
  PART_SYSTEM = 12,
  PART_MISC = 15,
};

struct datetime
{
  uint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t hour;
  uint8_t min;
  uint8_t sec;
  uint8_t reserve;
} __attribute__((packed));

struct header
{
  uint8_t fw_tag[4];
  struct datetime dt_release;
  uint8_t fw_version[4];
  uint32_t size;
  uint32_t partition_offset;
  uint32_t backup_partition_offset;
  uint32_t partition_size;
  uint32_t partition_count;
  uint32_t fw_size;
  uint8_t reserved[464];
  uint32_t partition_crc;
  uint32_t header_crc;
} __attribute__((packed));

struct partition
{
  uint8_t name[32];
  enum partition_type type;
  uint32_t offset;
  uint32_t size;
  uint32_t data_size;
  uint32_t property;
  uint8_t reserved[76];
} __attribute__((packed));

struct partition_info
{
  struct header header;
  struct partition partitions[12];
} __attribute__((packed));

struct kernel_header
{
  uint8_t tag[6];
  uint8_t zero[10];
  uint32_t load_address;
  uint32_t size;
  uint32_t crc;
  uint32_t checksum_length;
  uint8_t checksum[32];
} __attribute__((packed));

#endif
