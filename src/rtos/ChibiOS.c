/***************************************************************************
 *   Copyright (C) 2012 by Matthias Blaicher                               *
 *   Matthias Blaicher - matthias@blaicher.com                             *
 *                                                                         *
 *   Based on the excelent work by Evan Hunter                             *
 *   Copyright (C) 2011 by Broadcom Corporation                            *
 *   Evan Hunter - ehunter@broadcom.com                                    *
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

#include <helper/time_support.h>
#include <jtag/jtag.h>
#include "target/target.h"
#include "target/target_type.h"
#include "rtos.h"
#include "helper/log.h"
#include "rtos_chibios_stackings.h"
#include "rtos_standard_stackings.h"


/**
 * @brief   ChibiOS/RT memory signature record.
 *
 * @details Definition copied from os/kernel/include/chregistry.h of ChibiOS/RT.
 */
struct ChibiOS_chroot {
	char      ch_identifier[4];       /**< @brief Always set to "CHRT".       */
	uint8_t   ch_size;                /**< @brief Size of this structure.     */
	uint8_t   ch_reserved5;           /**< @brief Reserved field.             */
	uint16_t  ch_version;             /**< @brief Encoded ChibiOS/RT version. */
	uint8_t   ch_ptrsize;             /**< @brief Size of a pointer.          */
	uint8_t   ch_timesize;            /**< @brief Size of a @p systime_t.     */
	uint8_t   ch_threadsize;          /**< @brief Size of a @p Thread struct. */
	uint8_t   cf_off_prio;            /**< @brief Offset of @p p_prio field.  */
	uint8_t   cf_off_ctx;             /**< @brief Offset of @p p_ctx field.   */
	uint8_t   cf_off_newer;           /**< @brief Offset of @p p_newer field. */
	uint8_t   cf_off_older;           /**< @brief Offset of @p p_older field. */
	uint8_t   cf_off_name;            /**< @brief Offset of @p p_name field.  */
	uint8_t   cf_off_stklimit;        /**< @brief Offset of @p p_stklimit
												field.                      */
	uint8_t   cf_off_state;           /**< @brief Offset of @p p_state field. */
	uint8_t   cf_off_flags;           /**< @brief Offset of @p p_flags field. */
	uint8_t   cf_off_refs;            /**< @brief Offset of @p p_refs field.  */
	uint8_t   cf_off_preempt;         /**< @brief Offset of @p p_preempt
												field.                      */
	uint8_t   cf_off_time;            /**< @brief Offset of @p p_time field.  */
};

#define GET_CH_KERNEL_MAJOR(codedVersion) ((codedVersion >> 11) & 0x1f)
#define GET_CH_KERNEL_MINOR(codedVersion) ((codedVersion >> 6 ) & 0x1f)
#define GET_CH_KERNEL_PATCH(codedVersion) ((codedVersion >> 0 ) & 0x3f)

/**
 * @brief ChibiOS thread states.
 */
const char* ChibiOS_thread_states[] = {
	"READY", "CURRENT", "SUSPENDED", "WTSEM", "WTMTX", "WTCOND", "SLEEPING",
	"WTEXIT", "WTOREVT", "WTANDEVT", "SNDMSGQ", "SNDMSG", "WTMSG", "WTQUEUE",
	"FINAL"
};

#define CHIBIOS_NUM_STATES (sizeof(ChibiOS_thread_states)/sizeof(char *))


struct ChibiOS_params {
	const char *target_name;

	struct ChibiOS_chroot *ch_root;
	const struct rtos_register_stacking *stacking_info;
};

struct ChibiOS_params ChibiOS_params_list[] = {
	{
	"cortex_m3",							/* target_name */
	0,
	&rtos_chibios_Cortex_M3_stacking,		/* stacking_info */
	}
};
#define CHIBIOS_NUM_PARAMS ((int)(sizeof(ChibiOS_params_list)/sizeof(struct ChibiOS_params)))

static int ChibiOS_detect_rtos(struct target *target);
static int ChibiOS_create(struct target *target);
static int ChibiOS_update_threads(struct rtos *rtos);
static int ChibiOS_get_thread_reg_list(struct rtos *rtos, int64_t thread_id, char **hex_reg_list);
static int ChibiOS_get_symbol_list_to_lookup(symbol_table_elem_t *symbol_list[]);

struct rtos_type ChibiOS_rtos = {
	.name = "ChibiOS",

	.detect_rtos = ChibiOS_detect_rtos,
	.create = ChibiOS_create,
	.update_threads = ChibiOS_update_threads,
	.get_thread_reg_list = ChibiOS_get_thread_reg_list,
	.get_symbol_list_to_lookup = ChibiOS_get_symbol_list_to_lookup,
};

enum ChibiOS_symbol_values {
	ChibiOS_VAL_rlist = 0,
	ChibiOS_VAL_ch_root = 1
};

static char *ChibiOS_symbol_list[] = {
	"rlist",
	"ch_root",
	NULL
};

#define CHIBIOS_NUM_SYMBOLS (sizeof(ChibiOS_symbol_list)/sizeof(char *))


static int ChibiOS_update_memory_signature(struct rtos *rtos) {
	int retval;
	struct ChibiOS_params *param;

	param = (struct ChibiOS_params *) rtos->rtos_specific_params;

	/* Free existing memory description.*/
	if (param->ch_root) {
		free(param->ch_root);
		param->ch_root = 0;
	}

	param->ch_root = malloc(sizeof(struct ChibiOS_chroot));

	retval = target_read_buffer(rtos->target,
								rtos->symbols[ChibiOS_VAL_ch_root].address,
								sizeof(struct ChibiOS_chroot),
								(uint8_t *) param->ch_root);
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read ChibiOS Memory signature from target");
		goto errfree;
	}

	if (strncmp(param->ch_root->ch_identifier, "CHRT", 4) != 0) {
		LOG_ERROR("Memory signature identifier does not contain CHRT");
		retval = -1;
		goto errfree;
	}

	if (param->ch_root->ch_size < sizeof(struct ChibiOS_chroot)) {
		LOG_ERROR("ChibiOS/RT memory signature claimed to be smaller than expected");
		retval = -2;
		goto errfree;
	}

	if (param->ch_root->ch_size > sizeof(struct ChibiOS_chroot)) {
		LOG_WARNING("ChibiOS/RT memory signature claimed to be bigger than expected. "
					"Assuming compatibility...");
	}

	/* Convert endianness of version string */
	const uint8_t* versionTarget = (const uint8_t*) &param->ch_root->ch_version;
	param->ch_root->ch_version = rtos->target->endianness == TARGET_LITTLE_ENDIAN ?
			le_to_h_u32(versionTarget) : be_to_h_u32(versionTarget);

	const uint16_t ch_version = param->ch_root->ch_version;
	LOG_INFO("Successfully loaded memory map of ChibiOS/RT target running version %i.%i.%i",
		GET_CH_KERNEL_MAJOR(ch_version), GET_CH_KERNEL_MINOR(ch_version),
		GET_CH_KERNEL_PATCH(ch_version));

	return 0;

errfree:
	/* Error reading the ChibiOS memory structure */
	free(param->ch_root);
	param->ch_root = 0;
	return retval;
}

static int ChibiOS_update_threads(struct rtos *rtos)
{
	int i=0;
	int retval;
	const struct ChibiOS_params *param;
	int tasks_found = 0;
	
	int rtos_valid = -1;

	if (rtos->rtos_specific_params == NULL)
		return -1;

	if (rtos->symbols == NULL) {
		LOG_ERROR("No symbols for ChibiOS");
		return -3;
	}

	param = (const struct ChibiOS_params *) rtos->rtos_specific_params;
	
	/* Update the memory signature saved in the target memory */
	if (!param->ch_root) {
		retval = ChibiOS_update_memory_signature(rtos);
		if (retval != ERROR_OK) {
			LOG_ERROR("Reading the memory signature of ChibiOS/RT failed");
			return retval;
		}
	}

	/* wipe out previous thread details if any */
	if (rtos->thread_details != NULL) {
		int j;
		for (j = 0; j < rtos->thread_count; j++) {
			if (rtos->thread_details[j].display_str != NULL) {
				free(rtos->thread_details[j].display_str);
				rtos->thread_details[j].display_str = NULL;
			}
			if (rtos->thread_details[j].thread_name_str != NULL) {
				free(rtos->thread_details[j].thread_name_str);
				rtos->thread_details[j].thread_name_str = NULL;
			}
			if (rtos->thread_details[j].extra_info_str != NULL) {
				free(rtos->thread_details[j].extra_info_str);
				rtos->thread_details[j].extra_info_str = NULL;
			}
		}
		free(rtos->thread_details);
		rtos->thread_details = NULL;
		rtos->thread_count = 0;
	}
	
	/* ChibiOS does not save the current thread count.
	 * Parsing the double linked list to check for errors and number of threads. */
	uint32_t rlist;
	uint32_t current;
	uint32_t previous;
	uint32_t older;

	retval = target_read_buffer(rtos->target,
		rtos->symbols[ChibiOS_VAL_rlist].address,
		param->ch_root->ch_ptrsize,
		(uint8_t *)&rlist);
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read ChibiOS ReadyList from target");
		return retval;
	}
	
	current = rlist;
	previous = rlist;
	
	while(true) {
		LOG_DEBUG("Investigating ChibiOS task %i\r\n", tasks_found);
		
		retval = target_read_buffer(rtos->target,
			current + param->ch_root->cf_off_newer,
			param->ch_root->ch_ptrsize,
			(uint8_t *)&current);
		if (retval != ERROR_OK) {
			LOG_ERROR("Could not read next ChibiOS thread");
			return retval;
		}
		
		// Could be NULL if the kernel is not initialized yet or if the
		// registry is corrupted.
		if(current == 0) {
			LOG_ERROR("ChibiOS registry integrity check failed, NULL pointer");

			rtos_valid = 0;
			break;
		}
		
		// Fetch previous thread in the list as a integrity check.
		retval = target_read_buffer(rtos->target,
		  current + param->ch_root->cf_off_older,
		  param->ch_root->ch_ptrsize,
		  (uint8_t *)&older);
		if((retval != ERROR_OK) || (older==0) || (older!=previous)) {
			LOG_ERROR("ChibiOS registry integrity check failed, "
						"double linked list violation");
			rtos_valid = 0;
			break;
		}
		
		// Check for full iteration of the linked list.
		if(current==rlist)
			break;
		
		
		tasks_found++;
		
		previous = current;
	}
	
	LOG_DEBUG("Finished checking the ChibiOS thread registry.\r\n");
	

	if (!rtos_valid) {
		/* No RTOS threads - there is always at least the current execution though */
		LOG_INFO("Only showing current execution because of broken ChibiOS thread registry.");

		const char tmp_thread_name_str[] = "Current Execution";
		const char tmp_thread_extra_info_str[] = "No RTOS thread";

		rtos->thread_details = (struct thread_detail *) malloc(sizeof(struct thread_detail));
		rtos->thread_details->threadid = 1;
		rtos->thread_details->exists = true;
		rtos->thread_details->display_str = NULL;
		rtos->thread_details->extra_info_str = (char *) malloc(sizeof(tmp_thread_extra_info_str));
		strcpy(rtos->thread_details->extra_info_str, tmp_thread_extra_info_str);
		rtos->thread_details->thread_name_str = (char *) malloc(sizeof(tmp_thread_name_str));
		strcpy(rtos->thread_details->thread_name_str, tmp_thread_name_str);

		rtos->current_thread = 1;
		rtos->thread_count = 1;
		return ERROR_OK;
	}

	/* create space for new thread details */
	rtos->thread_details = (struct thread_detail *) malloc(
			sizeof(struct thread_detail) * tasks_found);
	rtos->thread_count = tasks_found;
	
	/* Loop through linked list. */
	i = 0;
	while (true) {
		uint32_t name_ptr = 0;
		
		#define CHIBIOS_THREAD_NAME_STR_SIZE (64)
		char tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE];

		retval = target_read_buffer(rtos->target,
									current + param->ch_root->cf_off_newer,
									param->ch_root->ch_ptrsize,
									(uint8_t *)&current);
		if (retval != ERROR_OK) {
			LOG_ERROR("Could not read next ChibiOS thread");
			return -6;
		}

		// Check for full iteration of the linked list.
		if (current == rlist)
			break;

		LOG_DEBUG("Exporting ChibiOS task %i\r\n", i);

		/* Save the thread pointer */
		rtos->thread_details[i].threadid = current;

		/* read the name pointer */
		retval = target_read_buffer(rtos->target,
									current + param->ch_root->cf_off_name,
									param->ch_root->ch_ptrsize,
									(uint8_t *)&name_ptr);
		if (retval != ERROR_OK) {
			LOG_ERROR("Could not read ChibiOS thread name pointer from target");
			return retval;
		}

		/* Read the thread name */
		retval = target_read_buffer(rtos->target, name_ptr,
									CHIBIOS_THREAD_NAME_STR_SIZE,
									(uint8_t *)&tmp_str);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error reading thread name from ChibiOS target");
			return retval;
		}
		tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE - 1] = '\x00';

		if (tmp_str[0] == '\x00')
			strcpy(tmp_str, "No Name");

		rtos->thread_details[i].thread_name_str = (char *)malloc(
				strlen(tmp_str) + 1);
		strcpy(rtos->thread_details[i].thread_name_str, tmp_str);

		/* State info */
		uint8_t threadState;
		const char *state_desc;

		retval = target_read_buffer(rtos->target,
									current + param->ch_root->cf_off_state,
									1, &threadState);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error reading thread state from ChibiOS target");
			return retval;
		}


		if (threadState < CHIBIOS_NUM_STATES)
			state_desc = ChibiOS_thread_states[threadState];
		else
			state_desc = "Unknown state";

		LOG_DEBUG("Thread in state %i (%s)\r\n", threadState, state_desc);

		rtos->thread_details[i].extra_info_str = (char *)malloc(strlen(
					state_desc)+1);
		strcpy(rtos->thread_details[i].extra_info_str, state_desc);

		rtos->thread_details[i].exists = true;
		rtos->thread_details[i].display_str = NULL;

		i++;
	}
	
	
	retval = target_read_buffer(rtos->target,
			  rlist + param->ch_root->cf_off_name, //FIXME: should be readylist_current_offset
			  param->ch_root->ch_ptrsize,
			  (uint8_t *)&rtos->current_thread);
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read current Thread from ChibiOS target");
		return retval;
	}
	
	LOG_DEBUG("Current thread is %i", (int) rtos->current_thread);
	
	return 0;
}

static int ChibiOS_get_thread_reg_list(struct rtos *rtos, int64_t thread_id, char **hex_reg_list)
{
	int retval;
	const struct ChibiOS_params *param;
	int64_t stack_ptr = 0;

	*hex_reg_list = NULL;
	if (rtos == NULL)
		return -1;

	if (thread_id == 0)
		return -2;

	if (rtos->rtos_specific_params == NULL)
		return -1;


	param = (const struct ChibiOS_params *) rtos->rtos_specific_params;

	if (param->ch_root == NULL)
		return -1;

	/* Read the stack pointer */
	retval = target_read_buffer(rtos->target,
			thread_id + param->ch_root->cf_off_ctx,
			param->ch_root->ch_ptrsize,
			(uint8_t *)&stack_ptr);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error reading stack frame from ChibiOS thread");
		return retval;
	}

	return rtos_generic_stack_read(rtos->target, param->stacking_info, stack_ptr, hex_reg_list);
}

static int ChibiOS_get_symbol_list_to_lookup(symbol_table_elem_t *symbol_list[])
{
	unsigned int i;
	*symbol_list = (symbol_table_elem_t *) malloc(
			sizeof(symbol_table_elem_t) * CHIBIOS_NUM_SYMBOLS);

	for (i = 0; i < CHIBIOS_NUM_SYMBOLS; i++)
		(*symbol_list)[i].symbol_name = ChibiOS_symbol_list[i];

	return 0;
}

static int ChibiOS_detect_rtos(struct target *target)
{
	if ((target->rtos->symbols != NULL) &&
			(target->rtos->symbols[ChibiOS_VAL_rlist].address != 0)) {
		/* looks like ChibiOS */
		return 1;
	}
	return 0;
}

static int ChibiOS_create(struct target *target)
{
	int i = 0;
	while ((i < CHIBIOS_NUM_PARAMS) &&
			(0 != strcmp(ChibiOS_params_list[i].target_name, target->type->name))) {
		i++;
	}
	if (i >= CHIBIOS_NUM_PARAMS) {
		LOG_WARNING("Could not find target in ChibiOS compatibility list");
		return -1;
	}

	target->rtos->rtos_specific_params = (void *) &ChibiOS_params_list[i];
	return 0;
}
