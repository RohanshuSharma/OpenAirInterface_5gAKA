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

#include "PDUSessionResourceToReleaseListHOCmd.hpp"

namespace ngap {

//------------------------------------------------------------------------------
PDUSessionResourceToReleaseListHOCmd::PDUSessionResourceToReleaseListHOCmd() {}

//------------------------------------------------------------------------------
PDUSessionResourceToReleaseListHOCmd::~PDUSessionResourceToReleaseListHOCmd() {}

//------------------------------------------------------------------------------
void PDUSessionResourceToReleaseListHOCmd::set(
    const std::vector<PDUSessionResourceItem>& list) {
  item_list_ = list;
}

//------------------------------------------------------------------------------
void PDUSessionResourceToReleaseListHOCmd::get(
    std::vector<PDUSessionResourceItem>& list) {
  list = item_list_;
}

//------------------------------------------------------------------------------
bool PDUSessionResourceToReleaseListHOCmd::encode(
    Ngap_PDUSessionResourceToReleaseListHOCmd_t& list) const {
  for (auto& item : item_list_) {
    Ngap_PDUSessionResourceToReleaseItemHOCmd_t* rel =
        (Ngap_PDUSessionResourceToReleaseItemHOCmd_t*) calloc(
            1, sizeof(Ngap_PDUSessionResourceToReleaseItemHOCmd_t));
    if (!rel) return false;
    if (!item.encode(rel)) return false;
    if (ASN_SEQUENCE_ADD(&list.list, rel) != 0) return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PDUSessionResourceToReleaseListHOCmd::decode(
    const Ngap_PDUSessionResourceToReleaseListHOCmd_t& list) {
  for (int i = 0; i < list.list.count; i++) {
    PDUSessionResourceItem item = {};
    if (!item.decode(list.list.array[i])) return false;
    item_list_.push_back(item);
  }
  return true;
}

}  // namespace ngap
