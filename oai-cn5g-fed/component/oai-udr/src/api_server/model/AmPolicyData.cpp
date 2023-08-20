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
/**
 * Nudr_DataRepository API OpenAPI file
 * Unified Data Repository Service. © 2020, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 2.1.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "AmPolicyData.h"

namespace oai::udr::model {

AmPolicyData::AmPolicyData() {
  m_PraInfosIsSet  = false;
  m_SubscCatsIsSet = false;
}

AmPolicyData::~AmPolicyData() {}

void AmPolicyData::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const AmPolicyData& o) {
  j = nlohmann::json();
  if (o.praInfosIsSet() || !o.m_PraInfos.empty()) j["praInfos"] = o.m_PraInfos;
  if (o.subscCatsIsSet() || !o.m_SubscCats.empty())
    j["subscCats"] = o.m_SubscCats;
}

void from_json(const nlohmann::json& j, AmPolicyData& o) {
  if (j.find("praInfos") != j.end()) {
    j.at("praInfos").get_to(o.m_PraInfos);
    o.m_PraInfosIsSet = true;
  }
  if (j.find("subscCats") != j.end()) {
    j.at("subscCats").get_to(o.m_SubscCats);
    o.m_SubscCatsIsSet = true;
  }
}

std::map<std::string, PresenceInfo>& AmPolicyData::getPraInfos() {
  return m_PraInfos;
}
void AmPolicyData::setPraInfos(
    std::map<std::string, PresenceInfo> const& value) {
  m_PraInfos      = value;
  m_PraInfosIsSet = true;
}
bool AmPolicyData::praInfosIsSet() const {
  return m_PraInfosIsSet;
}
void AmPolicyData::unsetPraInfos() {
  m_PraInfosIsSet = false;
}
std::vector<std::string>& AmPolicyData::getSubscCats() {
  return m_SubscCats;
}
void AmPolicyData::setSubscCats(std::vector<std::string> const& value) {
  m_SubscCats      = value;
  m_SubscCatsIsSet = true;
}
bool AmPolicyData::subscCatsIsSet() const {
  return m_SubscCatsIsSet;
}
void AmPolicyData::unsetSubscCats() {
  m_SubscCatsIsSet = false;
}

}  // namespace oai::udr::model
