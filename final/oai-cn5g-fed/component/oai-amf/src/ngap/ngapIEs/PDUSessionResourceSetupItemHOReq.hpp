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

#ifndef _PDU_SESSION_RESOURCE_SETUP_ITEM_HO_REQ_H_
#define _PDU_SESSION_RESOURCE_SETUP_ITEM_HO_REQ_H_

#include "PDUSessionResourceItem.hpp"
#include "PDUSessionResourceSetupRequestTransfer.hpp"
#include "S-NSSAI.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupItemHOReq.h"
}

namespace ngap {

class PDUSessionResourceSetupItemHOReq : public PDUSessionResourceItem {
 public:
  PDUSessionResourceSetupItemHOReq();
  virtual ~PDUSessionResourceSetupItemHOReq();

  void set(
      const PDUSessionID& pdu_session_id, const S_NSSAI& s_nssai,
      const OCTET_STRING_t& handover_request_transfer);
  void get(
      PDUSessionID& pdu_session_id, S_NSSAI& s_nssai,
      OCTET_STRING_t& handover_request_transfer);

  bool encode(Ngap_PDUSessionResourceSetupItemHOReq_t*
                  pduSessionResourceSetupItemHOReq);
  bool decode(Ngap_PDUSessionResourceSetupItemHOReq_t*
                  pduSessionResourceSetupItemHOReq);

 private:
  // PDUSessionID - Mandatory;
  S_NSSAI s_NSSAI;  // Mandatory
  // Handover Request Transfer - Mandatory
};

}  // namespace ngap

#endif
