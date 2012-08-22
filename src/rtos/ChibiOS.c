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

const char* ChibiOS_thread_states[] = {
  "READY",
  "CURRENT",
  "SUSPENDED",
  "WTSEM",
  "WTMTX",
  "WTCOND",
  "SLEEPING",
  "WTEXIT",
  "WTOREVT",
  "WTANDEVT",
  "SNDMSGQ",
  "SNDMSG",
  "WTMSG",
  "WTQUEUE",
  "FINAL"
};

#define CHIBIOS_NUM_STATES (sizeof(ChibiOS_thread_states)/sizeof(char *))



struct ChibiOS_params {
	const char *target_name;
	
	const unsigned char pointer_width;
	
	const unsigned char thread_prio_offset;
	const unsigned char thread_prio_size;
	
	const unsigned char thread_state_offset;
	const unsigned char thread_state_size;
	
	const unsigned char thread_ctx_offset;
	const unsigned char thread_ctx_size;
	
	const unsigned char thread_newer_offset;
	const unsigned char thread_older_offset;
	
	const unsigned char thread_name_offset;
	const unsigned char readylist_current_offset;
	
	const struct rtos_register_stacking *stacking_info;
};

const struct ChibiOS_params ChibiOS_params_list[] = {
	{
	"cortex_m3",	/* target_name */
	 
	4,				/* pointer_width */
	
	8, 				/* thread_prio_offset */
	4,				/* thread_prio_size */
	
	32,				/* thread_state_offset */
	1, 				/* thread_state_size */

	12,				/* thread_ctx_offset */
	4,				/* thread_ctx_size */

	16,				/* thread_newer_offset */
	20,				/* thread_older_offset */
	
	24,				/* thread_name_offset */
	24,				/* readylist_current_offset */
	
	&rtos_standard_Cortex_M3_stacking,		/* stacking_info */
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
};

static char *ChibiOS_symbol_list[] = {
	"rlist",
	NULL
};

#define CHIBIOS_NUM_SYMBOLS (sizeof(ChibiOS_symbol_list)/sizeof(char *))

static int ChibiOS_update_threads(struct rtos *rtos)
{
	LOG_OUTPUT("-------ChibiOS_update_threads()\r\n");
	
	int i=0;
	int retval;
	const struct ChibiOS_params *param;
	int tasks_found = 0;
	
	if (rtos->rtos_specific_params == NULL)
		return -1;

	param = (const struct ChibiOS_params *) rtos->rtos_specific_params;
	if (rtos->symbols == NULL) {
		LOG_OUTPUT("No symbols for ChibiOS\r\n");
		return -3;
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
	}
	
	/* ChibiOS does not save the current thread count.
	 * Parsing the double linked list to check for errors and number of threads. */
	
	uint32_t rlist;
	uint32_t current;
	uint32_t previous;
	uint32_t older;

	retval = target_read_buffer(rtos->target,
		rtos->symbols[ChibiOS_VAL_rlist].address,
		param->pointer_width,
		(uint8_t *)&rlist);
	if (retval != ERROR_OK) {
		LOG_OUTPUT("Could not read ChibiOS ReadyList from target\r\n");
		return retval;
	}
	
	current = rlist;
	previous = rlist;
	
	while(true) {
		LOG_OUTPUT("Investigating ChibiOS task %i\r\n", tasks_found);
		
	  	retval = target_read_buffer(rtos->target,
		  current + param->thread_newer_offset,
		  param->pointer_width,
		  (uint8_t *)&current);
		if (retval != ERROR_OK) {
			LOG_OUTPUT("Could not read next ChibiOS thread\r\n");
			LOG_OUTPUT("ChibiOS registry might not be enabled in kernel "
						"or your stack is corrupted\r\n");
			return retval;
		}
		
		// Current be NULL if the kernel is not initialized yet or if the
		// registry is corrupted.
		if(current == 0) {
		  LOG_OUTPUT("ChibiOS registry integrity check failed, NULL pointer\r\n");
		  return -4;
		}
		
		// Fetch previous thread in the list as a integrity check.
		retval = target_read_buffer(rtos->target,
		  current + param->thread_older_offset,
		  param->pointer_width,
		  (uint8_t *)&older);
		if((retval != ERROR_OK) || (older==0) || (older!=previous)) {
		  LOG_OUTPUT("ChibiOS registry integrity check failed, "
					  "double linked list violation\r\n");
		  LOG_OUTPUT("Also make sure that you have the thread "
					  "registry enabled!\r\n");
		  return -5;
		}
		
		// Check for full iteration of the linked list.
		if(current==rlist)
		  break;
		
		
		tasks_found++;
		
		previous = current;
	}
	
	LOG_OUTPUT("Finished checking the thread registry.\r\n");
	
	
	/* create space for new thread details */
	rtos->thread_details = (struct thread_detail *) malloc(
			sizeof(struct thread_detail) * tasks_found);
	rtos->thread_count = tasks_found;
	
	/* Loop through linked list. */
	i = 0;
	while(true) {
	  uint32_t name_ptr = 0;
	  #define CHIBIOS_THREAD_NAME_STR_SIZE (64)
	  char tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE];
		
	  LOG_OUTPUT("Exporting ChibiOS task %i\r\n", i);
	  
	  retval = target_read_buffer(rtos->target,
		current + param->thread_newer_offset,
		param->pointer_width,
		(uint8_t *)&current);
	  if (retval != ERROR_OK) {
		LOG_OUTPUT("Could not read next ChibiOS thread\r\n");
		return -6;
	  }
	  
	  // Check for full iteration of the linked list.
	  if(current==rlist)
		break;
	  
	  /* Save the thread pointer */
	  rtos->thread_details[i].threadid = current;
	  
	  /* read the name pointer */
	  retval = target_read_buffer(rtos->target,
			  current + param->thread_name_offset,
			  param->pointer_width,
			  (uint8_t *)&name_ptr);
	  if (retval != ERROR_OK) {
		  LOG_OUTPUT("Could not read ChibiOS thread name pointer from target\r\n");
		  return retval;
	  }
	  
	  /* Read the thread name */
	  retval =
		  target_read_buffer(rtos->target,
			  name_ptr,
			  CHIBIOS_THREAD_NAME_STR_SIZE,
			  (uint8_t *)&tmp_str);
	  if (retval != ERROR_OK) {
		  LOG_OUTPUT("Error reading thread name from ChibiOS target\r\n");
		  return retval;
	  }
	  tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE-1] = '\x00';
	
	  if (tmp_str[0] == '\x00')
			strcpy(tmp_str, "No Name");
	  
	  rtos->thread_details[i].thread_name_str = (char *)malloc(strlen(tmp_str)+1);
	  strcpy(rtos->thread_details[i].thread_name_str, tmp_str);
	  
	  /* TODO: State info */
	  rtos->thread_details[i].extra_info_str = NULL;
	  
	  
	  rtos->thread_details[i].exists = true;
	  rtos->thread_details[i].display_str = NULL;
	  
	  i++;
	}
	
	
	retval = target_read_buffer(rtos->target,
			  rlist + param->readylist_current_offset,
			  param->pointer_width,
			  (uint8_t *)&rtos->current_thread);
	if (retval != ERROR_OK) {
		LOG_OUTPUT("Could not read current Thread from ChibiOS target\r\n");
		return retval;
	}
	
	
	return 0;
}

static int ChibiOS_get_thread_reg_list(struct rtos *rtos, int64_t thread_id, char **hex_reg_list)
{
	LOG_OUTPUT("-------ChibiOS_get_thread_reg_list()\r\n");
  
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

	/* Read the stack pointer */
	retval = target_read_buffer(rtos->target,
			thread_id + param->thread_ctx_offset,
			param->pointer_width,
			(uint8_t *)&stack_ptr);
	if (retval != ERROR_OK) {
		LOG_OUTPUT("Error reading stack frame from ChibiOS thread\r\n");
		return retval;
	}

	return rtos_generic_stack_read(rtos->target, param->stacking_info, stack_ptr, hex_reg_list);

}

static int ChibiOS_get_symbol_list_to_lookup(symbol_table_elem_t *symbol_list[])
{
  	LOG_OUTPUT("-------ChibiOS_get_symbol_list_to_lookup()\r\n");
	unsigned int i;
	*symbol_list = (symbol_table_elem_t *) malloc(
			sizeof(symbol_table_elem_t) * CHIBIOS_NUM_SYMBOLS);

	for (i = 0; i < CHIBIOS_NUM_SYMBOLS; i++)
		(*symbol_list)[i].symbol_name = ChibiOS_symbol_list[i];

	return 0;
}

#if 0

static int ChibiOS_set_current_thread(struct rtos *rtos, threadid_t thread_id)
{
	return 0;
}

static int ChibiOS_get_thread_ascii_info(struct rtos *rtos, threadid_t thread_id, char **info)
{
	int retval;
	const struct ChibiOS_params *param;

	if (rtos == NULL)
		return -1;

	if (thread_id == 0)
		return -2;

	if (rtos->rtos_specific_params == NULL)
		return -3;

	param = (const struct ChibiOS_params *) rtos->rtos_specific_params;

#define CHIBIOS_THREAD_NAME_STR_SIZE (200)
	char tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE];

	/* Read the thread name */
	retval = target_read_buffer(rtos->target,
			thread_id + param->thread_name_offset,
			CHIBIOS_THREAD_NAME_STR_SIZE,
			(uint8_t *)&tmp_str);
	if (retval != ERROR_OK) {
		LOG_OUTPUT("Error reading first thread item location in ChibiOS thread list\r\n");
		return retval;
	}
	tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE-1] = '\x00';

	if (tmp_str[0] == '\x00')
		strcpy(tmp_str, "No Name");

	*info = (char *)malloc(strlen(tmp_str)+1);
	strcpy(*info, tmp_str);
	return 0;
}

#endif

static int ChibiOS_detect_rtos(struct target *target)
{
	LOG_OUTPUT("-------ChibiOS_detect_rtos()\r\n");
	if ((target->rtos->symbols != NULL) &&
			(target->rtos->symbols[ChibiOS_VAL_rlist].address != 0)) {
		/* looks like ChibiOS */
		return 1;
	}
	return 0;
}

static int ChibiOS_create(struct target *target)
{
	LOG_OUTPUT("-------ChibiOS_create()\r\n");
	int i = 0;
	while ((i < CHIBIOS_NUM_PARAMS) &&
			(0 != strcmp(ChibiOS_params_list[i].target_name, target->type->name))) {
		i++;
	}
	if (i >= CHIBIOS_NUM_PARAMS) {
		LOG_OUTPUT("Could not find target in ChibiOS compatibility list\r\n");
		return -1;
	}

	target->rtos->rtos_specific_params = (void *) &ChibiOS_params_list[i];
	return 0;
}
