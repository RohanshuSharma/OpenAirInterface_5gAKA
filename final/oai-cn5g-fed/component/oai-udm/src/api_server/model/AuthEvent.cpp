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
 * Nudm_UEAU
 * UDM UE Authentication Service. � 2020, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.2.0-alpha.1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "AuthEvent.h"

namespace oai {
namespace udm {
namespace model {

AuthEvent::AuthEvent() {
  m_NfInstanceId        = "";
  m_Success             = false;
  m_TimeStamp           = "";
  m_AuthType            = "";
  m_ServingNetworkName  = "";
  m_AuthRemovalInd      = false;
  m_AuthRemovalIndIsSet = false;
}

AuthEvent::~AuthEvent() {}

void AuthEvent::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const AuthEvent& o) {
  j                       = nlohmann::json();
  j["nfInstanceId"]       = o.m_NfInstanceId;
  j["success"]            = o.m_Success;
  j["timeStamp"]          = o.m_TimeStamp;
  j["authType"]           = o.m_AuthType;
  j["servingNetworkName"] = o.m_ServingNetworkName;
  if (o.authRemovalIndIsSet()) j["authRemovalInd"] = o.m_AuthRemovalInd;
}

void from_json(const nlohmann::json& j, AuthEvent& o) {
  j.at("nfInstanceId").get_to(o.m_NfInstanceId);
  j.at("success").get_to(o.m_Success);
  j.at("timeStamp").get_to(o.m_TimeStamp);
  j.at("authType").get_to(o.m_AuthType);
  j.at("servingNetworkName").get_to(o.m_ServingNetworkName);
  if (j.find("authRemovalInd") != j.end()) {
    j.at("authRemovalInd").get_to(o.m_AuthRemovalInd);
    o.m_AuthRemovalIndIsSet = true;
  }
}

std::string AuthEvent::getNfInstanceId() const {
  return m_NfInstanceId;
}
void AuthEvent::setNfInstanceId(std::string const& value) {
  m_NfInstanceId = value;
}
bool AuthEvent::isSuccess() const {
  return m_Success;
}
void AuthEvent::setSuccess(bool const value) {
  m_Success = value;
}
std::string AuthEvent::getTimeStamp() const {
  return m_TimeStamp;
}
void AuthEvent::setTimeStamp(std::string const& value) {
  m_TimeStamp = value;
}
std::string AuthEvent::getAuthType() const {
  return m_AuthType;
}
void AuthEvent::setAuthType(std::string const& value) {
  m_AuthType = value;
}
std::string AuthEvent::getServingNetworkName() const {
  return m_ServingNetworkName;
}
void AuthEvent::setServingNetworkName(std::string const& value) {
  m_ServingNetworkName = value;
}
bool AuthEvent::isAuthRemovalInd() const {
  return m_AuthRemovalInd;
}
void AuthEvent::setAuthRemovalInd(bool const value) {
  m_AuthRemovalInd      = value;
  m_AuthRemovalIndIsSet = true;
}
bool AuthEvent::authRemovalIndIsSet() const {
  return m_AuthRemovalIndIsSet;
}
void AuthEvent::unsetAuthRemovalInd() {
  m_AuthRemovalIndIsSet = false;
}

}  // namespace model
}  // namespace udm
}  // namespace oai
