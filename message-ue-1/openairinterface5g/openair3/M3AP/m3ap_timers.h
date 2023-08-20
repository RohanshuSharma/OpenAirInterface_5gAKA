/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef M3AP_TIMERS_H_
#define M3AP_TIMERS_H_

#include <stdint.h>
#include "platform_types.h"

typedef struct {
  /* incremented every TTI (every millisecond when in realtime).
   * Used to check timers.
   * 64 bits gives us more than 500 million years of (realtime) processing.
   * It should be enough.
   */
  uint64_t tti;

  /* timer values (unit: TTI, ie. millisecond when in realtime) */
  int      t_reloc_prep;
  int      tm3_reloc_overall;
} m3ap_timers_t;

void m3ap_timers_init(m3ap_timers_t *t, int t_reloc_prep, int tm3_reloc_overall);
void m3ap_check_timers(instance_t instance);
uint64_t m3ap_timer_get_tti(m3ap_timers_t *t);

#endif /* M3AP_TIMERS_H_ */
