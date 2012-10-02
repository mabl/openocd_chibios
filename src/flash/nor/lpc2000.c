/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   LPC1700 support Copyright (C) 2009 by Audrius Urmanavicius            *
 *   didele.deze@gmail.com                                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/arm_opcodes.h>
#include <target/armv7m.h>

/**
 * @file
 * flash programming support for NXP LPC17xx and LPC2xxx devices.
 *
 * @todo Provide a way to update CCLK after declaring the flash bank.
 * The value which is correct after chip reset will rarely still work
 * right after the clocks switch to use the PLL (e.g. 4MHz --> 100 MHz).
 */
/*
 * currently supported devices:
 * variant 1 (lpc2000_v1):
 * - 2104 | 5 | 6
 * - 2114 | 9
 * - 2124 | 9
 * - 2194
 * - 2212 | 4
 * - 2292 | 4
 *
 * variant 2 (lpc2000_v2):
 * - 213x
 * - 214x
 * - 2101 | 2 | 3
 * - 2364 | 6 | 8
 * - 2378
 *
 * lpc1700:
 * - 175x
 * - 176x (tested with LPC1768)
 */

typedef enum {
	lpc2000_v1,
	lpc2000_v2,
	lpc1700
} lpc2000_variant;

struct lpc2000_flash_bank {
	lpc2000_variant variant;
	struct working_area *iap_working_area;
	uint32_t cclk;
	int cmd51_dst_boundary;
	int cmd51_can_256b;
	int cmd51_can_8192b;
	int calc_checksum;
	uint32_t cmd51_max_buffer;
	int checksum_vector;
};

enum lpc2000_status_codes {
	LPC2000_CMD_SUCCESS = 0,
	LPC2000_INVALID_COMMAND = 1,
	LPC2000_SRC_ADDR_ERROR = 2,
	LPC2000_DST_ADDR_ERROR = 3,
	LPC2000_SRC_ADDR_NOT_MAPPED = 4,
	LPC2000_DST_ADDR_NOT_MAPPED = 5,
	LPC2000_COUNT_ERROR = 6,
	LPC2000_INVALID_SECTOR = 7,
	LPC2000_SECTOR_NOT_BLANK = 8,
	LPC2000_SECTOR_NOT_PREPARED = 9,
	LPC2000_COMPARE_ERROR = 10,
	LPC2000_BUSY = 11,
	LPC2000_PARAM_ERROR = 12,
	LPC2000_ADDR_ERROR = 13,
	LPC2000_ADDR_NOT_MAPPED = 14,
	LPC2000_CMD_NOT_LOCKED = 15,
	LPC2000_INVALID_CODE = 16,
	LPC2000_INVALID_BAUD_RATE = 17,
	LPC2000_INVALID_STOP_BIT = 18,
	LPC2000_CRP_ENABLED = 19
};

static int lpc2000_build_sector_list(struct flash_bank *bank)
{
	struct lpc2000_flash_bank *lpc2000_info = bank->driver_priv;
	int i;
	uint32_t offset = 0;

	/* default to a 4096 write buffer */
	lpc2000_info->cmd51_max_buffer = 4096;

	if (lpc2000_info->variant == lpc2000_v1) {
		/* variant 1 has different layout for 128kb and 256kb flashes */
		if (bank->size == 128 * 1024) {
			bank->num_sectors = 16;
			bank->sectors = malloc(sizeof(struct flash_sector) * 16);
			for (i = 0; i < 16; i++) {
				bank->sectors[i].offset = offset;
				bank->sectors[i].size = 8 * 1024;
				offset += bank->sectors[i].size;
				bank->sectors[i].is_erased = -1;
				bank->sectors[i].is_protected = 1;
			}
		} else if (bank->size == 256 * 1024) {
			bank->num_sectors = 18;
			bank->sectors = malloc(sizeof(struct flash_sector) * 18);

			for (i = 0; i < 8; i++) {
				bank->sectors[i].offset = offset;
				bank->sectors[i].size = 8 * 1024;
				offset += bank->sectors[i].size;
				bank->sectors[i].is_erased = -1;
				bank->sectors[i].is_protected = 1;
			}
			for (i = 8; i < 10; i++) {
				bank->sectors[i].offset = offset;
				bank->sectors[i].size = 64 * 1024;
				offset += bank->sectors[i].size;
				bank->sectors[i].is_erased = -1;
				bank->sectors[i].is_protected = 1;
			}
			for (i = 10; i < 18; i++) {
				bank->sectors[i].offset = offset;
				bank->sectors[i].size = 8 * 1024;
				offset += bank->sectors[i].size;
				bank->sectors[i].is_erased = -1;
				bank->sectors[i].is_protected = 1;
			}
		} else {
			LOG_ERROR("BUG: unknown bank->size encountered");
			exit(-1);
		}
	} else if (lpc2000_info->variant == lpc2000_v2) {
		/* variant 2 has a uniform layout, only number of sectors differs */
		switch (bank->size) {
			case 4 * 1024:
				lpc2000_info->cmd51_max_buffer = 1024;
				bank->num_sectors = 1;
				break;
			case 8 * 1024:
				lpc2000_info->cmd51_max_buffer = 1024;
				bank->num_sectors = 2;
				break;
			case 16 * 1024:
				bank->num_sectors = 4;
				break;
			case 32 * 1024:
				bank->num_sectors = 8;
				break;
			case 64 * 1024:
				bank->num_sectors = 9;
				break;
			case 128 * 1024:
				bank->num_sectors = 11;
				break;
			case 256 * 1024:
				bank->num_sectors = 15;
				break;
			case 500 * 1024:
				bank->num_sectors = 27;
				break;
			case 512 * 1024:
			case 504 * 1024:
				bank->num_sectors = 28;
				break;
			default:
				LOG_ERROR("BUG: unknown bank->size encountered");
				exit(-1);
				break;
		}

		bank->sectors = malloc(sizeof(struct flash_sector) * bank->num_sectors);

		for (i = 0; i < bank->num_sectors; i++) {
			if (i < 8) {
				bank->sectors[i].offset = offset;
				bank->sectors[i].size = 4 * 1024;
				offset += bank->sectors[i].size;
				bank->sectors[i].is_erased = -1;
				bank->sectors[i].is_protected = 1;
			} else if (i < 22) {
				bank->sectors[i].offset = offset;
				bank->sectors[i].size = 32 * 1024;
				offset += bank->sectors[i].size;
				bank->sectors[i].is_erased = -1;
				bank->sectors[i].is_protected = 1;
			} else if (i < 28) {
				bank->sectors[i].offset = offset;
				bank->sectors[i].size = 4 * 1024;
				offset += bank->sectors[i].size;
				bank->sectors[i].is_erased = -1;
				bank->sectors[i].is_protected = 1;
			}
		}
	} else if (lpc2000_info->variant == lpc1700) {
		switch (bank->size) {
			case 32 * 1024:
				bank->num_sectors = 8;
				break;
			case 64 * 1024:
				bank->num_sectors = 16;
				break;
			case 128 * 1024:
				bank->num_sectors = 18;
			break;
			case 256 * 1024:
				bank->num_sectors = 22;
				break;
			case 512 * 1024:
				bank->num_sectors = 30;
				break;
			default:
				LOG_ERROR("BUG: unknown bank->size encountered");
				exit(-1);
		}

		bank->sectors = malloc(sizeof(struct flash_sector) * bank->num_sectors);

		for (i = 0; i < bank->num_sectors; i++) {
			bank->sectors[i].offset = offset;
			/* sectors 0-15 are 4kB-sized, 16 and above are 32kB-sized for LPC17xx
			 *devices */
			bank->sectors[i].size = (i < 16) ? 4 * 1024 : 32 * 1024;
			offset += bank->sectors[i].size;
			bank->sectors[i].is_erased = -1;
			bank->sectors[i].is_protected = 1;
		}
	} else {
		LOG_ERROR("BUG: unknown lpc2000_info->variant encountered");
		exit(-1);
	}

	return ERROR_OK;
}

/* call LPC1700/LPC2000 IAP function
 * uses 180 bytes working area
 * 0x0 to 0x7: jump gate (BX to thumb state, b -2 to wait)
 * 0x8 to 0x1f: command parameter table (1+5 words)
 * 0x20 to 0x33: command result table (1+4 words)
 * 0x34 to 0xb3: stack (only 128b needed)
 */
static int lpc2000_iap_call(struct flash_bank *bank,
	int code,
	uint32_t param_table[5],
	uint32_t result_table[4])
{
	int retval;
	struct lpc2000_flash_bank *lpc2000_info = bank->driver_priv;
	struct target *target = bank->target;
	struct mem_param mem_params[2];
	struct reg_param reg_params[5];
	struct arm_algorithm arm_algo;	/* for LPC2000 */
	struct armv7m_algorithm armv7m_info;	/* for LPC1700 */
	uint32_t status_code;
	uint32_t iap_entry_point = 0;	/* to make compiler happier */

	/* regrab previously allocated working_area, or allocate a new one */
	if (!lpc2000_info->iap_working_area) {
		uint8_t jump_gate[8];

		/* make sure we have a working area */
		if (target_alloc_working_area(target, 180,
				&lpc2000_info->iap_working_area) != ERROR_OK) {
			LOG_ERROR("no working area specified, can't write LPC2000 internal flash");
			return ERROR_FLASH_OPERATION_FAILED;
		}

		/* write IAP code to working area */
		switch (lpc2000_info->variant) {
			case lpc1700:
				target_buffer_set_u32(target, jump_gate, ARMV4_5_T_BX(12));
				target_buffer_set_u32(target, jump_gate + 4, ARMV5_T_BKPT(0));
				break;
			case lpc2000_v1:
			case lpc2000_v2:
				target_buffer_set_u32(target, jump_gate, ARMV4_5_BX(12));
				target_buffer_set_u32(target, jump_gate + 4, ARMV4_5_B(0xfffffe, 0));
				break;
			default:
				LOG_ERROR("BUG: unknown lpc2000_info->variant encountered");
				exit(-1);
		}

		retval = target_write_memory(target,
				lpc2000_info->iap_working_area->address, 4, 2, jump_gate);
		if (retval != ERROR_OK) {
			LOG_ERROR(
				"Write memory at address 0x%8.8" PRIx32 " failed (check work_area definition)",
				lpc2000_info->iap_working_area->address);
			return retval;
		}
	}

	switch (lpc2000_info->variant) {
		case lpc1700:
			armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
			armv7m_info.core_mode = ARMV7M_MODE_ANY;
			iap_entry_point = 0x1fff1ff1;
			break;
		case lpc2000_v1:
		case lpc2000_v2:
			arm_algo.common_magic = ARM_COMMON_MAGIC;
			arm_algo.core_mode = ARM_MODE_SVC;
			arm_algo.core_state = ARM_STATE_ARM;
			iap_entry_point = 0x7ffffff1;
			break;
		default:
			LOG_ERROR("BUG: unknown lpc2000->variant encountered");
			exit(-1);
	}

	/* command parameter table */
	init_mem_param(&mem_params[0], lpc2000_info->iap_working_area->address + 8, 6 * 4,
		PARAM_OUT);
	target_buffer_set_u32(target, mem_params[0].value, code);
	target_buffer_set_u32(target, mem_params[0].value + 0x04, param_table[0]);
	target_buffer_set_u32(target, mem_params[0].value + 0x08, param_table[1]);
	target_buffer_set_u32(target, mem_params[0].value + 0x0c, param_table[2]);
	target_buffer_set_u32(target, mem_params[0].value + 0x10, param_table[3]);
	target_buffer_set_u32(target, mem_params[0].value + 0x14, param_table[4]);

	init_reg_param(&reg_params[0], "r0", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, lpc2000_info->iap_working_area->address + 0x08);

	/* command result table */
	init_mem_param(&mem_params[1],
		lpc2000_info->iap_working_area->address + 0x20,
		5 * 4,
		PARAM_IN);

	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	buf_set_u32(reg_params[1].value, 0, 32, lpc2000_info->iap_working_area->address + 0x20);

	/* IAP entry point */
	init_reg_param(&reg_params[2], "r12", 32, PARAM_OUT);
	buf_set_u32(reg_params[2].value, 0, 32, iap_entry_point);

	switch (lpc2000_info->variant) {
		case lpc1700:
			/* IAP stack */
			init_reg_param(&reg_params[3], "sp", 32, PARAM_OUT);
			buf_set_u32(reg_params[3].value, 0, 32,
					lpc2000_info->iap_working_area->address + 0xb4);

			/* return address */
			init_reg_param(&reg_params[4], "lr", 32, PARAM_OUT);
			buf_set_u32(reg_params[4].value, 0, 32,
					(lpc2000_info->iap_working_area->address + 0x04) | 1);
			/* bit0 of LR = 1 to return in Thumb mode */

			target_run_algorithm(target, 2, mem_params, 5, reg_params,
					lpc2000_info->iap_working_area->address, 0, 10000, &armv7m_info);
			break;
		case lpc2000_v1:
		case lpc2000_v2:
			/* IAP stack */
			init_reg_param(&reg_params[3], "sp_svc", 32, PARAM_OUT);
			buf_set_u32(reg_params[3].value, 0, 32,
					lpc2000_info->iap_working_area->address + 0xb4);

			/* return address */
			init_reg_param(&reg_params[4], "lr_svc", 32, PARAM_OUT);
			buf_set_u32(reg_params[4].value, 0, 32,
					lpc2000_info->iap_working_area->address + 0x04);

			target_run_algorithm(target, 2, mem_params, 5, reg_params,
					lpc2000_info->iap_working_area->address,
					lpc2000_info->iap_working_area->address + 0x4,
					10000, &arm_algo);
			break;
		default:
			LOG_ERROR("BUG: unknown lpc2000->variant encountered");
			exit(-1);
	}

	status_code = target_buffer_get_u32(target, mem_params[1].value);
	result_table[0] = target_buffer_get_u32(target, mem_params[1].value + 0x04);
	result_table[1] = target_buffer_get_u32(target, mem_params[1].value + 0x08);
	result_table[2] = target_buffer_get_u32(target, mem_params[1].value + 0x0c);
	result_table[3] = target_buffer_get_u32(target, mem_params[1].value + 0x10);

	LOG_DEBUG("IAP command = %i (0x%8.8" PRIx32 ", 0x%8.8" PRIx32
			", 0x%8.8" PRIx32 ", 0x%8.8" PRIx32 ", 0x%8.8"
			PRIx32 ") completed with result = %8.8" PRIx32,
			code, param_table[0], param_table[1], param_table[2],
			param_table[3], param_table[4], status_code);

	destroy_mem_param(&mem_params[0]);
	destroy_mem_param(&mem_params[1]);

	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);
	destroy_reg_param(&reg_params[3]);
	destroy_reg_param(&reg_params[4]);

	return status_code;
}

static int lpc2000_iap_blank_check(struct flash_bank *bank, int first, int last)
{
	uint32_t param_table[5] = {0};
	uint32_t result_table[4];
	int status_code;
	int i;

	if ((first < 0) || (last >= bank->num_sectors))
		return ERROR_FLASH_SECTOR_INVALID;

	for (i = first; i <= last; i++) {
		/* check single sector */
		param_table[0] = param_table[1] = i;
		status_code = lpc2000_iap_call(bank, 53, param_table, result_table);

		switch (status_code) {
			case ERROR_FLASH_OPERATION_FAILED:
				return ERROR_FLASH_OPERATION_FAILED;
			case LPC2000_CMD_SUCCESS:
				bank->sectors[i].is_erased = 1;
				break;
			case LPC2000_SECTOR_NOT_BLANK:
				bank->sectors[i].is_erased = 0;
				break;
			case LPC2000_INVALID_SECTOR:
				bank->sectors[i].is_erased = 0;
				break;
			case LPC2000_BUSY:
				return ERROR_FLASH_BUSY;
				break;
			default:
				LOG_ERROR("BUG: unknown LPC2000 status code %i", status_code);
				exit(-1);
		}
	}

	return ERROR_OK;
}

/*
 * flash bank lpc2000 <base> <size> 0 0 <target#> <lpc_variant> <cclk> [calc_checksum]
 */
FLASH_BANK_COMMAND_HANDLER(lpc2000_flash_bank_command)
{
	struct lpc2000_flash_bank *lpc2000_info;

	if (CMD_ARGC < 8)
		return ERROR_COMMAND_SYNTAX_ERROR;

	lpc2000_info = malloc(sizeof(struct lpc2000_flash_bank));
	bank->driver_priv = lpc2000_info;

	if (strcmp(CMD_ARGV[6], "lpc2000_v1") == 0) {
		lpc2000_info->variant = lpc2000_v1;
		lpc2000_info->cmd51_dst_boundary = 512;
		lpc2000_info->cmd51_can_256b = 0;
		lpc2000_info->cmd51_can_8192b = 1;
		lpc2000_info->checksum_vector = 5;
	} else if (strcmp(CMD_ARGV[6], "lpc2000_v2") == 0) {
		lpc2000_info->variant = lpc2000_v2;
		lpc2000_info->cmd51_dst_boundary = 256;
		lpc2000_info->cmd51_can_256b = 1;
		lpc2000_info->cmd51_can_8192b = 0;
		lpc2000_info->checksum_vector = 5;
	} else if (strcmp(CMD_ARGV[6], "lpc1700") == 0) {
		lpc2000_info->variant = lpc1700;
		lpc2000_info->cmd51_dst_boundary = 256;
		lpc2000_info->cmd51_can_256b = 1;
		lpc2000_info->cmd51_can_8192b = 0;
		lpc2000_info->checksum_vector = 7;
	} else {
		LOG_ERROR("unknown LPC2000 variant: %s", CMD_ARGV[6]);
		free(lpc2000_info);
		return ERROR_FLASH_BANK_INVALID;
	}

	lpc2000_info->iap_working_area = NULL;
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[7], lpc2000_info->cclk);
	lpc2000_info->calc_checksum = 0;
	lpc2000_build_sector_list(bank);

	if (CMD_ARGC >= 9) {
		if (strcmp(CMD_ARGV[8], "calc_checksum") == 0)
			lpc2000_info->calc_checksum = 1;
	}

	return ERROR_OK;
}

static int lpc2000_erase(struct flash_bank *bank, int first, int last)
{
	struct lpc2000_flash_bank *lpc2000_info = bank->driver_priv;
	uint32_t param_table[5] = {0};
	uint32_t result_table[4];
	int status_code;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	param_table[0] = first;
	param_table[1] = last;
	param_table[2] = lpc2000_info->cclk;

	/* Prepare sectors */
	status_code = lpc2000_iap_call(bank, 50, param_table, result_table);
	switch (status_code) {
		case ERROR_FLASH_OPERATION_FAILED:
			return ERROR_FLASH_OPERATION_FAILED;
		case LPC2000_CMD_SUCCESS:
			break;
		case LPC2000_INVALID_SECTOR:
			return ERROR_FLASH_SECTOR_INVALID;
			break;
		default:
			LOG_WARNING("lpc2000 prepare sectors returned %i", status_code);
			return ERROR_FLASH_OPERATION_FAILED;
	}

	/* Erase sectors */
	status_code = lpc2000_iap_call(bank, 52, param_table, result_table);
	switch (status_code) {
		case ERROR_FLASH_OPERATION_FAILED:
			return ERROR_FLASH_OPERATION_FAILED;
		case LPC2000_CMD_SUCCESS:
			break;
		case LPC2000_INVALID_SECTOR:
			return ERROR_FLASH_SECTOR_INVALID;
			break;
		default:
			LOG_WARNING("lpc2000 erase sectors returned %i", status_code);
			return ERROR_FLASH_OPERATION_FAILED;
	}

	return ERROR_OK;
}

static int lpc2000_protect(struct flash_bank *bank, int set, int first, int last)
{
	/* can't protect/unprotect on the lpc2000 */
	return ERROR_OK;
}

static int lpc2000_write(struct flash_bank *bank, uint8_t *buffer, uint32_t offset, uint32_t count)
{
	struct lpc2000_flash_bank *lpc2000_info = bank->driver_priv;
	struct target *target = bank->target;
	uint32_t dst_min_alignment;
	uint32_t bytes_remaining = count;
	uint32_t bytes_written = 0;
	int first_sector = 0;
	int last_sector = 0;
	uint32_t param_table[5] = {0};
	uint32_t result_table[4];
	int status_code;
	int i;
	struct working_area *download_area;
	int retval = ERROR_OK;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (offset + count > bank->size)
		return ERROR_FLASH_DST_OUT_OF_BANK;

	dst_min_alignment = lpc2000_info->cmd51_dst_boundary;

	if (offset % dst_min_alignment) {
		LOG_WARNING("offset 0x%" PRIx32 " breaks required alignment 0x%" PRIx32,
			offset,
			dst_min_alignment);
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	for (i = 0; i < bank->num_sectors; i++) {
		if (offset >= bank->sectors[i].offset)
			first_sector = i;
		if (offset + DIV_ROUND_UP(count, dst_min_alignment)
				* dst_min_alignment > bank->sectors[i].offset)
			last_sector = i;
	}

	LOG_DEBUG("first_sector: %i, last_sector: %i", first_sector, last_sector);

	/* check if exception vectors should be flashed */
	if ((offset == 0) && (count >= 0x20) && lpc2000_info->calc_checksum) {
		uint32_t checksum = 0;
		for (i = 0; i < 8; i++) {
			LOG_DEBUG("Vector 0x%2.2x: 0x%8.8" PRIx32, i * 4,
				buf_get_u32(buffer + (i * 4), 0, 32));
			if (i != lpc2000_info->checksum_vector)
				checksum += buf_get_u32(buffer + (i * 4), 0, 32);
		}
		checksum = 0 - checksum;
		LOG_DEBUG("checksum: 0x%8.8" PRIx32, checksum);

		uint32_t original_value = buf_get_u32(buffer +
				(lpc2000_info->checksum_vector * 4), 0, 32);
		if (original_value != checksum) {
			LOG_WARNING("Verification will fail since checksum in image (0x%8.8" PRIx32 ") "
					"to be written to flash is different from calculated vector "
					"checksum (0x%8.8" PRIx32 ").", original_value, checksum);
			LOG_WARNING("To remove this warning modify build tools on developer PC "
					"to inject correct LPC vector checksum.");
		}

		buf_set_u32(buffer + (lpc2000_info->checksum_vector * 4), 0, 32, checksum);
	}

	/* allocate a working area */
	if (target_alloc_working_area(target, lpc2000_info->cmd51_max_buffer,
			&download_area) != ERROR_OK) {
		LOG_ERROR("no working area specified, can't write LPC2000 internal flash");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	while (bytes_remaining > 0) {
		uint32_t thisrun_bytes;
		if (bytes_remaining >= lpc2000_info->cmd51_max_buffer)
			thisrun_bytes = lpc2000_info->cmd51_max_buffer;
		else if (bytes_remaining >= 1024)
			thisrun_bytes = 1024;
		else if ((bytes_remaining >= 512) || (!lpc2000_info->cmd51_can_256b))
			thisrun_bytes = 512;
		else
			thisrun_bytes = 256;

		/* Prepare sectors */
		param_table[0] = first_sector;
		param_table[1] = last_sector;
		status_code = lpc2000_iap_call(bank, 50, param_table, result_table);
		switch (status_code) {
			case ERROR_FLASH_OPERATION_FAILED:
				retval = ERROR_FLASH_OPERATION_FAILED;
				break;
			case LPC2000_CMD_SUCCESS:
				break;
			case LPC2000_INVALID_SECTOR:
				retval = ERROR_FLASH_SECTOR_INVALID;
				break;
			default:
				LOG_WARNING("lpc2000 prepare sectors returned %i", status_code);
				retval = ERROR_FLASH_OPERATION_FAILED;
				break;
		}

		/* Exit if error occured */
		if (retval != ERROR_OK)
			break;

		if (bytes_remaining >= thisrun_bytes) {
			retval = target_write_buffer(bank->target, download_area->address,
					thisrun_bytes, buffer + bytes_written);
			if (retval != ERROR_OK) {
				retval = ERROR_FLASH_OPERATION_FAILED;
				break;
			}
		} else {
			uint8_t *last_buffer = malloc(thisrun_bytes);
			memcpy(last_buffer, buffer + bytes_written, bytes_remaining);
			memset(last_buffer + bytes_remaining, 0xff, thisrun_bytes -
				bytes_remaining);
			target_write_buffer(bank->target,
				download_area->address,
				thisrun_bytes,
				last_buffer);
			free(last_buffer);
		}

		LOG_DEBUG("writing 0x%" PRIx32 " bytes to address 0x%" PRIx32,
			thisrun_bytes,
			bank->base + offset + bytes_written);

		/* Write data */
		param_table[0] = bank->base + offset + bytes_written;
		param_table[1] = download_area->address;
		param_table[2] = thisrun_bytes;
		param_table[3] = lpc2000_info->cclk;
		status_code = lpc2000_iap_call(bank, 51, param_table, result_table);
		switch (status_code) {
			case ERROR_FLASH_OPERATION_FAILED:
				retval = ERROR_FLASH_OPERATION_FAILED;
				break;
			case LPC2000_CMD_SUCCESS:
				break;
			case LPC2000_INVALID_SECTOR:
				retval = ERROR_FLASH_SECTOR_INVALID;
				break;
			default:
				LOG_WARNING("lpc2000 returned %i", status_code);
				retval = ERROR_FLASH_OPERATION_FAILED;
				break;
		}

		/* Exit if error occured */
		if (retval != ERROR_OK)
			break;

		if (bytes_remaining > thisrun_bytes)
			bytes_remaining -= thisrun_bytes;
		else
			bytes_remaining = 0;
		bytes_written += thisrun_bytes;
	}

	target_free_working_area(target, download_area);

	return retval;
}

static int lpc2000_probe(struct flash_bank *bank)
{
	/* we can't probe on an lpc2000
	 * if this is an lpc2xxx, it has the configured flash
	 */
	return ERROR_OK;
}

static int lpc2000_erase_check(struct flash_bank *bank)
{
	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	return lpc2000_iap_blank_check(bank, 0, bank->num_sectors - 1);
}

static int lpc2000_protect_check(struct flash_bank *bank)
{
	/* sectors are always protected	*/
	return ERROR_OK;
}

static int get_lpc2000_info(struct flash_bank *bank, char *buf, int buf_size)
{
	struct lpc2000_flash_bank *lpc2000_info = bank->driver_priv;

	snprintf(buf,
		buf_size,
		"lpc2000 flash driver variant: %i, clk: %" PRIi32 "kHz",
		lpc2000_info->variant,
		lpc2000_info->cclk);

	return ERROR_OK;
}

COMMAND_HANDLER(lpc2000_handle_part_id_command)
{
	uint32_t param_table[5] = {0};
	uint32_t result_table[4];
	int status_code;

	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (ERROR_OK != retval)
		return retval;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	status_code = lpc2000_iap_call(bank, 54, param_table, result_table);
	if (status_code != 0x0) {
		if (status_code == ERROR_FLASH_OPERATION_FAILED) {
			command_print(CMD_CTX,
				"no sufficient working area specified, can't access LPC2000 IAP interface");
			return ERROR_OK;
		}
		command_print(CMD_CTX, "lpc2000 IAP returned status code %i", status_code);
	} else
		command_print(CMD_CTX, "lpc2000 part id: 0x%8.8" PRIx32, result_table[0]);

	return ERROR_OK;
}

static const struct command_registration lpc2000_exec_command_handlers[] = {
	{
		.name = "part_id",
		.handler = lpc2000_handle_part_id_command,
		.mode = COMMAND_EXEC,
		.help = "print part id of lpc2000 flash bank <num>",
		.usage = "<bank>",
	},
	COMMAND_REGISTRATION_DONE
};
static const struct command_registration lpc2000_command_handlers[] = {
	{
		.name = "lpc2000",
		.mode = COMMAND_ANY,
		.help = "lpc2000 flash command group",
		.usage = "",
		.chain = lpc2000_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver lpc2000_flash = {
	.name = "lpc2000",
	.commands = lpc2000_command_handlers,
	.flash_bank_command = lpc2000_flash_bank_command,
	.erase = lpc2000_erase,
	.protect = lpc2000_protect,
	.write = lpc2000_write,
	.read = default_flash_read,
	.probe = lpc2000_probe,
	.auto_probe = lpc2000_probe,
	.erase_check = lpc2000_erase_check,
	.protect_check = lpc2000_protect_check,
	.info = get_lpc2000_info,
};
