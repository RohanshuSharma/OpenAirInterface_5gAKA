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

#include "ReachabilityForDataConfiguration.h"
#include "Helpers.h"

#include <sstream>

namespace oai::udm::model {

ReachabilityForDataConfiguration::ReachabilityForDataConfiguration() {}

void ReachabilityForDataConfiguration::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::udm::helpers::ValidationException(msg.str());
  }
}

bool ReachabilityForDataConfiguration::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool ReachabilityForDataConfiguration::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "ReachabilityForDataConfiguration" : pathPrefix;

  return success;
}

bool ReachabilityForDataConfiguration::operator==(
    const ReachabilityForDataConfiguration& rhs) const {
  return

      (getReportCfg() == rhs.getReportCfg())

          ;
}

bool ReachabilityForDataConfiguration::operator!=(
    const ReachabilityForDataConfiguration& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ReachabilityForDataConfiguration& o) {
  j              = nlohmann::json();
  j["reportCfg"] = o.m_ReportCfg;
}

void from_json(const nlohmann::json& j, ReachabilityForDataConfiguration& o) {
  j.at("reportCfg").get_to(o.m_ReportCfg);
}

ReachabilityForDataReportConfig ReachabilityForDataConfiguration::getReportCfg()
    const {
  return m_ReportCfg;
}
void ReachabilityForDataConfiguration::setReportCfg(
    ReachabilityForDataReportConfig const& value) {
  m_ReportCfg = value;
}

}  // namespace oai::udm::model