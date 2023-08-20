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

#include "Lpi.h"

namespace oai::udr::model {

Lpi::Lpi() {
  m_ValidTimePeriodIsSet = false;
}

Lpi::~Lpi() {}

void Lpi::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const Lpi& o) {
  j                       = nlohmann::json();
  j["locationPrivacyInd"] = o.m_LocationPrivacyInd;
  if (o.validTimePeriodIsSet()) j["validTimePeriod"] = o.m_ValidTimePeriod;
}

void from_json(const nlohmann::json& j, Lpi& o) {
  j.at("locationPrivacyInd").get_to(o.m_LocationPrivacyInd);
  if (j.find("validTimePeriod") != j.end()) {
    j.at("validTimePeriod").get_to(o.m_ValidTimePeriod);
    o.m_ValidTimePeriodIsSet = true;
  }
}

LocationPrivacyInd Lpi::getLocationPrivacyInd() const {
  return m_LocationPrivacyInd;
}
void Lpi::setLocationPrivacyInd(LocationPrivacyInd const& value) {
  m_LocationPrivacyInd = value;
}
ValidTimePeriod Lpi::getValidTimePeriod() const {
  return m_ValidTimePeriod;
}
void Lpi::setValidTimePeriod(ValidTimePeriod const& value) {
  m_ValidTimePeriod      = value;
  m_ValidTimePeriodIsSet = true;
}
bool Lpi::validTimePeriodIsSet() const {
  return m_ValidTimePeriodIsSet;
}
void Lpi::unsetValidTimePeriod() {
  m_ValidTimePeriodIsSet = false;
}

}  // namespace oai::udr::model
