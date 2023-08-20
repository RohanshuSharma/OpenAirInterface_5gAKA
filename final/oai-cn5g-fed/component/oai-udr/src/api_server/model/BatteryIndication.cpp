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

#include "BatteryIndication.h"

namespace oai::udr::model {

BatteryIndication::BatteryIndication() {
  m_BatteryInd           = false;
  m_BatteryIndIsSet      = false;
  m_ReplaceableInd       = false;
  m_ReplaceableIndIsSet  = false;
  m_RechargeableInd      = false;
  m_RechargeableIndIsSet = false;
}

BatteryIndication::~BatteryIndication() {}

void BatteryIndication::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const BatteryIndication& o) {
  j = nlohmann::json();
  if (o.batteryIndIsSet()) j["batteryInd"] = o.m_BatteryInd;
  if (o.replaceableIndIsSet()) j["replaceableInd"] = o.m_ReplaceableInd;
  if (o.rechargeableIndIsSet()) j["rechargeableInd"] = o.m_RechargeableInd;
}

void from_json(const nlohmann::json& j, BatteryIndication& o) {
  if (j.find("batteryInd") != j.end()) {
    j.at("batteryInd").get_to(o.m_BatteryInd);
    o.m_BatteryIndIsSet = true;
  }
  if (j.find("replaceableInd") != j.end()) {
    j.at("replaceableInd").get_to(o.m_ReplaceableInd);
    o.m_ReplaceableIndIsSet = true;
  }
  if (j.find("rechargeableInd") != j.end()) {
    j.at("rechargeableInd").get_to(o.m_RechargeableInd);
    o.m_RechargeableIndIsSet = true;
  }
}

bool BatteryIndication::isBatteryInd() const {
  return m_BatteryInd;
}
void BatteryIndication::setBatteryInd(bool const value) {
  m_BatteryInd      = value;
  m_BatteryIndIsSet = true;
}
bool BatteryIndication::batteryIndIsSet() const {
  return m_BatteryIndIsSet;
}
void BatteryIndication::unsetBatteryInd() {
  m_BatteryIndIsSet = false;
}
bool BatteryIndication::isReplaceableInd() const {
  return m_ReplaceableInd;
}
void BatteryIndication::setReplaceableInd(bool const value) {
  m_ReplaceableInd      = value;
  m_ReplaceableIndIsSet = true;
}
bool BatteryIndication::replaceableIndIsSet() const {
  return m_ReplaceableIndIsSet;
}
void BatteryIndication::unsetReplaceableInd() {
  m_ReplaceableIndIsSet = false;
}
bool BatteryIndication::isRechargeableInd() const {
  return m_RechargeableInd;
}
void BatteryIndication::setRechargeableInd(bool const value) {
  m_RechargeableInd      = value;
  m_RechargeableIndIsSet = true;
}
bool BatteryIndication::rechargeableIndIsSet() const {
  return m_RechargeableIndIsSet;
}
void BatteryIndication::unsetRechargeableInd() {
  m_RechargeableIndIsSet = false;
}

}  // namespace oai::udr::model
