/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
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

#ifndef __5GS_IDENTITY_TYPE_H_
#define __5GS_IDENTITY_TYPE_H_

#include <stdint.h>
#include "bstrlib.h"

#define _5GS_IDENTITY_TYPE_MINIMUM_LENGTH 1
#define _5GS_IDENTITY_TYPE_MAXIMUM_LENGTH 1

#define IDENTITY_REQUEST_SUCI 0x01
#define IDENTITY_REQUEST_5G_GUTI 0x02
#define IDENTITY_REQUEST_IMEI 0x03
#define IDENTITY_REQUEST_5G_S_TMSI 0x04
#define IDENTITY_REQUEST_IMEISV 0x05

typedef struct {
  uint8_t typeOfIdentity : 3;
} _5GSIdentityType;

int encode__5gs_identity_type(
    _5GSIdentityType _5gsidentitytype, uint8_t iei, uint8_t* buffer,
    uint32_t len);
int decode__5gs_identity_type(
    _5GSIdentityType* _5gsidentitytype, uint8_t iei, uint8_t* buffer,
    uint32_t len);

#endif
