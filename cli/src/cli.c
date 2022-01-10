/* SPDX-License-Identifier: GPL-2.0 */

/* Copyright (c) 2022 William Durand */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cli.h"
#include "crc.h"

// For extract_kernel
#define OUTPUT_KERNEL_EXTRACTED "./kernel-extracted.bin"

// For (extract|make)_rkfp
#define OUTPUT_RKFP_IMAGE    "./image.bin"
#define OUTPUT_PARTITION_FMT "part-%s.bin"
#define INPUT_PARTITION_FMT  "%s/" OUTPUT_PARTITION_FMT

#define CRC_SIZE_FOR_HEADER (sizeof(struct header) - sizeof(uint32_t))
#define CRC_SIZE_FOR_PARTITIONS(hdr)                                           \
  (sizeof(struct partition) * (hdr).partition_count)

#define FLASH_SIZE_IN_BYTES 16777216

void usage_and_exit(const char* argv0)
{
  fprintf(stderr, "usage: %s <command> <args>\n\n", argv0);
  fprintf(stderr, "You are probably interested in one of these commands:\n\n");
  fprintf(stderr, "manipulate RKFP images\n");
  fprintf(stderr,
          "    %-30s Display information about a given RKFP image\n",
          "info <dump-file>");
  fprintf(stderr,
          "    %-30s Extract the content of a RKFP image. Multiple\n"
          "                                   output files will be created.\n",
          "extract_rkfp <dir>");
  fprintf(stderr,
          "    %-30s Make a RKFP image. Output file: '%s'\n\n",
          "make_rkfp <dir>",
          OUTPUT_RKFP_IMAGE);
  fprintf(stderr, "manipulate kernel images and partitions\n");
  fprintf(stderr,
          "    %-30s Extract the kernel image inside a kernel partition.\n"
          "                                   Output file: '%s'\n",
          "extract_kernel <part-file>",
          OUTPUT_KERNEL_EXTRACTED);

  exit(EXIT_FAILURE);
}

int write_partition(FILE* img,
                    struct partition_info* info,
                    const char* dir_path,
                    uint8_t partition,
                    const char* name,
                    uint32_t type,
                    uint32_t offset,
                    uint32_t size,
                    uint32_t property)
{

  char input_file[256];
  snprintf(input_file, sizeof(input_file), INPUT_PARTITION_FMT, dir_path, name);

  FILE* fp = fopen(input_file, "rb");
  if (!fp) {
    fprintf(stderr, "failed to open file for partition #%02u\n", partition);
    return -1;
  }

  fseek(fp, 0, SEEK_END);
  uint32_t data_size = (uint32_t)ftell(fp);
  rewind(fp);

  if (data_size > size) {
    fprintf(stderr, "input file size is greater than %X\n", size);
    fclose(fp);
    return -1;
  }

  printf("Writing partition: 0x%08X-0x%08X\n", offset, offset + size);
  printf("  name : %s\n", name);
  printf("  size : %" PRIu32 " bytes\n", data_size);
  printf("  file : %s\n", input_file);

  uint8_t* data = (uint8_t*)calloc(size, sizeof(uint8_t));
  if (!data) {
    fprintf(stderr, "failed to allocate data memory\n");
    fclose(fp);
    return -1;
  }

  memset(data, 0, size);

  if (fread(data, 1, data_size, fp) != data_size) {
    fprintf(stderr, "failed to read file for partition #%02u\n", partition);
    free(data);
    fclose(fp);
    return -1;
  }

  fclose(fp);

  info->partitions[partition] = (struct partition){
    .name = "",
    .type = type,
    .offset = offset / info->header.size,
    .size = size / info->header.size,
    .data_size = data_size,
    .property = property,
    // Not sure why but some dumps have data in this reserved area...
    .reserved = { 0 },
  };

  // There is something I don't understand with the IDBlock partition:
  // basically, after we write the actual content (whose size is 0x10000),
  // there is more data written but I cannot figure out how that is computed.
  //
  // 2021-01-09 - I modified `extract_rkfp` to dump the entire partition so
  // that I can use it with `make_rkfp`, but we need to patch the data size
  // below...
  //
  // 2021-01-11 - It looks like we have two loaders in this partition, but
  // somehow the data size does not capture that.
  if (type == PART_IDBLOCK) {
    info->partitions[partition].data_size = 0x10000;
  }

  strcpy((char*)&info->partitions[partition].name, name);

  fseek(img, offset, SEEK_SET);
  if (fwrite((void*)data, 1, size, img) != size) {
    fprintf(stderr, "failed to write data for partition #%02u\n", partition);
    return -1;
  }

  return 0;
}

void print_kernel_header(struct kernel_header* header)
{
  printf("kernel header:\n");
  printf("  load address: 0x%08X\n", header->load_address);
  printf(
    "  kernel size : %" PRIu32 " bytes (%08X)\n", header->size, header->size);
  printf("  crc         : %08X\n", header->crc);
  printf("  checksum len: %" PRIu32 "\n", header->checksum_length);
  printf("  checksum    :");
  for (uint8_t i = 0; i < 32; i++) {
    printf(" %02X", header->checksum[i]);
    if (i == 15) {
      printf("\n               ");
    }
  }
  printf("\n");
}

int info(int argc, char* argv[])
{
  FILE* fp = fopen(argv[2], "rb");
  if (!fp) {
    fprintf(stderr, "failed to open file");
    return EXIT_FAILURE;
  }

  fseek(fp, 0, SEEK_END);
  uint32_t file_size = (uint32_t)ftell(fp);
  rewind(fp);

  printf("Input file:\n");
  printf("  name: %s\n", argv[2]);
  printf("  size: %d bytes\n", file_size);
  printf("\n");

  uint8_t* buffer = (uint8_t*)calloc(file_size, sizeof(uint8_t));
  if (!buffer) {
    fprintf(stderr, "failed to allocate buffer");
    fclose(fp);
    return EXIT_FAILURE;
  }

  if (fread(buffer, 1, file_size, fp) != file_size) {
    fprintf(stderr, "failed to read file");
    fclose(fp);
    return EXIT_FAILURE;
  }

  fclose(fp);

  struct partition_info* info = (struct partition_info*)buffer;

  struct header* hdr = &info->header;

  if (memcmp(hdr->fw_tag, "RKFP", 4) != 0) {
    fprintf(stderr, "invalid fw_tag number");
    free(buffer);
    return EXIT_FAILURE;
  }

  printf("Header:\n");
  printf("  firmware tag           : %c%c%c%c\n",
         hdr->fw_tag[0],
         hdr->fw_tag[1],
         hdr->fw_tag[2],
         hdr->fw_tag[3]);
  printf("  firmware version       : %02d.%02d.%02d\n",
         hdr->fw_version[3],
         hdr->fw_version[2],
         (hdr->fw_version[1] << 8) + hdr->fw_version[0]);
  printf("  release date           : %04d-%02d-%02d at %02d:%02d:%02d\n",
         hdr->dt_release.year,
         hdr->dt_release.month,
         hdr->dt_release.day,
         hdr->dt_release.hour,
         hdr->dt_release.min,
         hdr->dt_release.sec);
  printf("  size                   : %" PRIu32 " bytes\n", hdr->size);
  printf("  partition_offset       : %" PRIu32 " sectors\n",
         hdr->partition_offset);
  printf("  backup_partition_offset: %" PRIu32 " sectors\n",
         hdr->backup_partition_offset);
  printf("  partition_size         : %" PRIu32 " bytes\n", hdr->partition_size);
  printf("  partition_count        : %" PRIu32 "\n", hdr->partition_count);
  printf("  fw_size                : %" PRIu32 " bytes\n", hdr->fw_size);
  printf("  partition_crc          : 0x%08X\n", hdr->partition_crc);
  printf("  header_crc             : 0x%08X\n", hdr->header_crc);
  printf("\n");

  printf("CRC:\n");
  uint32_t header_crc = crc32(0, buffer, CRC_SIZE_FOR_HEADER);
  if (header_crc == hdr->header_crc) {
    printf("  header CRC   : OK\n");
  } else {
    printf("  WARNING! header CRC mismatch (got 0x%08X)\n", header_crc);
  }

  uint32_t partition_crc =
    crc32(0, buffer + hdr->size, CRC_SIZE_FOR_PARTITIONS(*hdr));
  if (partition_crc == hdr->partition_crc) {
    printf("  partition CRC: OK\n");
  } else {
    printf("  WARNING! partition CRC mismatch (got 0x%08X)\n", partition_crc);
  }
  printf("\n");

  uint32_t size = hdr->size;

  for (uint8_t i = 0; i < hdr->partition_count; i++) {
    const struct partition* p = &info->partitions[i];

    printf("Partition #%02u - 0x%08X-0x%08X\n",
           i,
           p->offset * size,
           (p->offset + p->size) * size);
    printf("  name     : %s\n", p->name);
    printf("  type     : 0x%02X\n", p->type);
    printf(
      "  offset   : %8u bytes (0x%X)\n", p->offset * size, p->offset * size);
    printf("  size     : %8u bytes (0x%X)\n", p->size * size, p->size * size);
    printf("  data size: %8u bytes (0x%X)\n", p->data_size, p->data_size);
    printf("  property : 0x%02X\n", p->property);
    printf("\n");
  }

  free(buffer);

  return EXIT_SUCCESS;
}

int extract_rkfp(int argc, char* argv[])
{
  FILE* fp = fopen(argv[2], "rb");
  if (!fp) {
    fprintf(stderr, "failed to open dump file");
    return EXIT_FAILURE;
  }

  fseek(fp, 0, SEEK_END);
  uint32_t file_size = (uint32_t)ftell(fp);
  rewind(fp);

  uint8_t* buffer = (uint8_t*)calloc(file_size, sizeof(uint8_t));
  if (!buffer) {
    fprintf(stderr, "failed to allocate memory");
    fclose(fp);
    return EXIT_FAILURE;
  }

  if (fread(buffer, file_size, 1, fp) != 1) {
    fprintf(stderr, "failed to read dump file");
    fclose(fp);
    return EXIT_FAILURE;
  }

  fclose(fp);

  struct partition_info* info = (struct partition_info*)buffer;

  struct header* hdr = &info->header;

  if (memcmp(hdr->fw_tag, "RKFP", 4) != 0) {
    fprintf(stderr, "the dump file is not a RKFP image");
    free(buffer);
    return EXIT_FAILURE;
  }

  uint32_t size = hdr->size;

  for (uint8_t i = 0; i < hdr->partition_count; i++) {
    const struct partition* p = &info->partitions[i];

    char out_file[256];
    snprintf(out_file, sizeof(out_file), OUTPUT_PARTITION_FMT, p->name);

    FILE* out = fopen(out_file, "wb");
    if (!out) {
      fprintf(stderr, "failed to open file '%s'", out_file);
      free(buffer);
      return EXIT_FAILURE;
    }

    uint32_t out_size = p->data_size;

    printf("Extracting partition: 0x%08X-0x%08X\n",
           p->offset * size,
           (p->offset + p->size) * size);
    printf("  name       : %s\n", p->name);
    printf("  size       : %" PRIu32 " bytes", out_size);

    if (p->type == PART_IDBLOCK) {
      out_size = p->size * size;
      printf(" (extracting %" PRIu32
             " bytes because it is a IDBlock partition)",
             out_size);
    }

    printf("\n");
    printf("  output file: %s\n", out_file);

    if (fwrite(buffer + (p->offset * size), 1, out_size, out) != out_size) {
      fprintf(stderr, "failed to write to file '%s'", out_file);
      fclose(out);
      free(buffer);
      return EXIT_FAILURE;
    }

    fclose(out);
  }

  free(buffer);

  return EXIT_SUCCESS;
}

int make_rkfp(int argc, char* argv[])
{
  printf("Making kernel partition: %s...\n", OUTPUT_RKFP_IMAGE);

  FILE* fp = fopen(OUTPUT_RKFP_IMAGE, "wb");
  if (!fp) {
    fprintf(stderr, "failed to create file");
    return EXIT_FAILURE;
  }

  time_t now = time(NULL);
  struct tm* lt = localtime(&now);

  struct partition_info info = {};
  info.header = (struct header){
    .fw_tag = { 'R', 'K', 'F', 'P' },
    .dt_release =
      (struct datetime){
        .year = (uint16_t)(1900 + lt->tm_year),
        .month = (uint8_t)(1 + lt->tm_mon),
        .day = (uint8_t)lt->tm_mday,
        .hour = (uint8_t)lt->tm_hour,
        .min = (uint8_t)lt->tm_min,
        .sec = (uint8_t)lt->tm_sec,
      },
    .fw_version = { 0x19, 0x00, 0x05, 0x10 },
    .size = 0x200,
    .partition_offset = 1,
    .backup_partition_offset = 32752,
    .partition_size = 128,
    .partition_count = 6,
    .fw_size = 0,
    .reserved = { 0 },
  };

  const char* dir_path = argv[2];

  // Partition #00: vendor
  if (write_partition(
        fp, &info, dir_path, 0, "vendor", PART_VENDOR, 0x1000, 0x7000, 0x00) !=
      0) {
    fprintf(stderr, "aborting...");
    fclose(fp);
    return EXIT_FAILURE;
  }

  uint32_t property = 0x00;

  // Partition #01: IDBlock
  if (write_partition(fp,
                      &info,
                      dir_path,
                      1,
                      "IDBlock",
                      PART_IDBLOCK,
                      0x8000,
                      0x30000,
                      property) != 0) {
    fprintf(stderr, "aborting...");
    fclose(fp);
    return EXIT_FAILURE;
  }

  // TODO: can we dynamically compute the partition sizes of the kernel, data
  // and system, based on their contents?

  // Partition #02: kernel
  if (write_partition(fp,
                      &info,
                      dir_path,
                      2,
                      "kernel",
                      PART_KERNEL,
                      0x40000,
                      0x400000,
                      property) != 0) {
    fprintf(stderr, "aborting...");
    fclose(fp);
    return EXIT_FAILURE;
  }

  // Partition #03: data
  if (write_partition(fp,
                      &info,
                      dir_path,
                      3,
                      "data",
                      PART_BOOT,
                      0x440000,
                      0xC0000,
                      property) != 0) {
    fprintf(stderr, "aborting...");
    fclose(fp);
    return EXIT_FAILURE;
  }

  // Partition #04: system
  if (write_partition(fp,
                      &info,
                      dir_path,
                      4,
                      "system",
                      PART_SYSTEM,
                      0x500000,
                      0xAFD000,
                      property) != 0) {
    fprintf(stderr, "aborting...");
    fclose(fp);
    return EXIT_FAILURE;
  }

  // Partition #05: misc
  if (write_partition(fp,
                      &info,
                      dir_path,
                      5,
                      "misc",
                      PART_MISC,
                      0xFFD000,
                      0x1000,
                      property) != 0) {
    fprintf(stderr, "aborting...");
    fclose(fp);
    return EXIT_FAILURE;
  }

  // TODO: add a CLI flag to enable this, maybe?
#ifdef ADD_BACKUP_METADATA
  // Write backup metadata after the partitions.
  uint32_t backup_size = 4096 * sizeof(uint8_t);
  uint8_t* backup = (uint8_t*)calloc(1, backup_size);
  if (!backup) {
    fprintf(stderr, "failed to allocate memory for backup metadata");
    fclose(fp);
    return EXIT_FAILURE;
  }

  memset(backup, 0, backup_size);
  memcpy(backup, (void*)&info + 0x200, 0x380);
  memcpy(backup + 0xe00, (void*)&info, 0x80);
  fwrite(backup, 1, backup_size, fp);
  free(backup);
#endif

  info.header.partition_crc =
    crc32(0, (uint8_t*)&info.partitions, CRC_SIZE_FOR_PARTITIONS(info.header));
  info.header.header_crc =
    crc32(0, (uint8_t*)&info.header, CRC_SIZE_FOR_HEADER);

  fseek(fp, 0, SEEK_SET);
  if (fwrite((void*)&info, 1, sizeof(struct partition_info), fp) !=
      sizeof(struct partition_info)) {
    fprintf(stderr, "failed to write partition information");
    fclose(fp);
    return EXIT_FAILURE;
  }

  // Make sure the image file has the right size for the flash.
  fflush(fp);
  ftruncate(fileno(fp), FLASH_SIZE_IN_BYTES);

  fclose(fp);

  printf("Success!\n");

  return EXIT_SUCCESS;
}

int extract_kernel(int argc, char* argv[])
{
  FILE* fp = fopen(argv[2], "rb");
  if (!fp) {
    fprintf(stderr, "failed to open file");
    return EXIT_FAILURE;
  }

  uint8_t header_data[0x800];
  fread(header_data, 1, sizeof(header_data), fp);

  struct kernel_header* header = (struct kernel_header*)header_data;
  uint32_t kernel_size = header->size;

  uint8_t* data = (uint8_t*)calloc(kernel_size, sizeof(uint8_t));
  if (!data) {
    fprintf(stderr, "failed to allocate memory");
    return EXIT_FAILURE;
  }

  printf("Unpacking kernel image...\n");
  print_kernel_header(header);

  fseek(fp, 0x800, SEEK_SET);
  fread(data, 1, kernel_size, fp);
  fclose(fp);

  FILE* out = fopen(OUTPUT_KERNEL_EXTRACTED, "wb");
  if (!out) {
    fprintf(stderr, "failed to open '%s' file", OUTPUT_KERNEL_EXTRACTED);
    return EXIT_FAILURE;
  }

  fwrite(data, 1, kernel_size, out);
  fclose(out);

  printf("Success!\n");

  free(data);

  return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
  if (argc < 3) {
    usage_and_exit(argv[0]);
  }

  if (!strcmp(argv[1], "info")) {
    return info(argc, argv);
  } else if (!strcmp(argv[1], "extract_rkfp")) {
    return extract_rkfp(argc, argv);
  } else if (!strcmp(argv[1], "make_rkfp")) {
    return make_rkfp(argc, argv);
  } else if (!strcmp(argv[1], "extract_kernel")) {
    return extract_kernel(argc, argv);
  }

  usage_and_exit(argv[0]);
}
