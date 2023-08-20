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

#ifndef _UE_RADIO_CAPABILITY_H_
#define _UE_RADIO_CAPABILITY_H_

#include "bstrlib.h"

extern "C" {
#include "Ngap_UERadioCapability.h"
}

namespace ngap {

class UERadioCapability {
 public:
  UERadioCapability();
  virtual ~UERadioCapability();

  bool encode(Ngap_UERadioCapability_t& ueRadioCapability);
  bool decode(Ngap_UERadioCapability_t& ueRadioCapability);

  bool set(const OCTET_STRING_t& capability);
  bool get(OCTET_STRING_t& capability);

  bool set(const bstring& capability);
  bool get(bstring& capability);

 private:
  OCTET_STRING_t ue_radio_capability_;
};

}  // namespace ngap

#endif
