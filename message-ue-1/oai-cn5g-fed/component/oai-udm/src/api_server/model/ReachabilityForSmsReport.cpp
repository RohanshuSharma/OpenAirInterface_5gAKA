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
 * Nudm_EE
 * Nudm Event Exposure Service. © 2021, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.2.0-alpha.3
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "ReachabilityForSmsReport.h"
#include "Helpers.h"

#include <sstream>

namespace oai::udm::model {

ReachabilityForSmsReport::ReachabilityForSmsReport() {
  m_MaxAvailabilityTime      = "";
  m_MaxAvailabilityTimeIsSet = false;
}

void ReachabilityForSmsReport::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::udm::helpers::ValidationException(msg.str());
  }
}

bool ReachabilityForSmsReport::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool ReachabilityForSmsReport::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "ReachabilityForSmsReport" : pathPrefix;

  return success;
}

bool ReachabilityForSmsReport::operator==(
    const ReachabilityForSmsReport& rhs) const {
  return true;
  // TODO
  /*


  (getSmsfAccessType() == rhs.getSmsfAccessType())
   &&


  ((!maxAvailabilityTimeIsSet() && !rhs.maxAvailabilityTimeIsSet()) ||
  (maxAvailabilityTimeIsSet() && rhs.maxAvailabilityTimeIsSet() &&
  getMaxAvailabilityTime() == rhs.getMaxAvailabilityTime()))

  ;
  */
}

bool ReachabilityForSmsReport::operator!=(
    const ReachabilityForSmsReport& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ReachabilityForSmsReport& o) {
  j                   = nlohmann::json();
  j["smsfAccessType"] = o.m_SmsfAccessType;
  if (o.maxAvailabilityTimeIsSet())
    j["maxAvailabilityTime"] = o.m_MaxAvailabilityTime;
}

void from_json(const nlohmann::json& j, ReachabilityForSmsReport& o) {
  j.at("smsfAccessType").get_to(o.m_SmsfAccessType);
  if (j.find("maxAvailabilityTime") != j.end()) {
    j.at("maxAvailabilityTime").get_to(o.m_MaxAvailabilityTime);
    o.m_MaxAvailabilityTimeIsSet = true;
  }
}

AccessType ReachabilityForSmsReport::getSmsfAccessType() const {
  return m_SmsfAccessType;
}
void ReachabilityForSmsReport::setSmsfAccessType(AccessType const& value) {
  m_SmsfAccessType = value;
}
std::string ReachabilityForSmsReport::getMaxAvailabilityTime() const {
  return m_MaxAvailabilityTime;
}
void ReachabilityForSmsReport::setMaxAvailabilityTime(
    std::string const& value) {
  m_MaxAvailabilityTime      = value;
  m_MaxAvailabilityTimeIsSet = true;
}
bool ReachabilityForSmsReport::maxAvailabilityTimeIsSet() const {
  return m_MaxAvailabilityTimeIsSet;
}
void ReachabilityForSmsReport::unsetMaxAvailabilityTime() {
  m_MaxAvailabilityTimeIsSet = false;
}

}  // namespace oai::udm::model
