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
/*
 * HssAuthenticationInfoRequest.h
 *
 *
 */

#ifndef HssAuthenticationInfoRequest_H_
#define HssAuthenticationInfoRequest_H_

#include <nlohmann/json.hpp>
#include <string>

#include "AccessNetworkId.h"
#include "HssAuthType.h"
#include "NodeType.h"
#include "PlmnId.h"
#include "ResynchronizationInfo.h"
using namespace oai::udm::model;
namespace oai {
namespace udm {
namespace model {

/// <summary>
///
/// </summary>
class HssAuthenticationInfoRequest {
 public:
  HssAuthenticationInfoRequest();
  virtual ~HssAuthenticationInfoRequest();

  void validate();

  /////////////////////////////////////////////
  /// HssAuthenticationInfoRequest members

  /// <summary>
  ///
  /// </summary>
  std::string getSupportedFeatures() const;
  void setSupportedFeatures(std::string const& value);
  bool supportedFeaturesIsSet() const;
  void unsetSupportedFeatures();
  /// <summary>
  ///
  /// </summary>
  HssAuthType getHssAuthType() const;
  void setHssAuthType(HssAuthType const& value);
  /// <summary>
  ///
  /// </summary>
  int32_t getNumOfRequestedVectors() const;
  void setNumOfRequestedVectors(int32_t const value);
  /// <summary>
  ///
  /// </summary>
  NodeType getRequestingNodeType() const;
  void setRequestingNodeType(NodeType const& value);
  bool requestingNodeTypeIsSet() const;
  void unsetRequestingNodeType();
  /// <summary>
  ///
  /// </summary>
  PlmnId getServingNetworkId() const;
  void setServingNetworkId(PlmnId const& value);
  bool servingNetworkIdIsSet() const;
  void unsetServingNetworkId();
  /// <summary>
  ///
  /// </summary>
  ResynchronizationInfo getResynchronizationInfo() const;
  void setResynchronizationInfo(ResynchronizationInfo const& value);
  bool resynchronizationInfoIsSet() const;
  void unsetResynchronizationInfo();
  /// <summary>
  ///
  /// </summary>
  AccessNetworkId getAnId() const;
  void setAnId(AccessNetworkId const& value);
  bool anIdIsSet() const;
  void unsetAnId();

  friend void to_json(nlohmann::json& j, const HssAuthenticationInfoRequest& o);
  friend void from_json(
      const nlohmann::json& j, HssAuthenticationInfoRequest& o);

 protected:
  std::string m_SupportedFeatures;
  bool m_SupportedFeaturesIsSet;
  HssAuthType m_HssAuthType;

  int32_t m_NumOfRequestedVectors;

  NodeType m_RequestingNodeType;
  bool m_RequestingNodeTypeIsSet;
  PlmnId m_ServingNetworkId;
  bool m_ServingNetworkIdIsSet;
  ResynchronizationInfo m_ResynchronizationInfo;
  bool m_ResynchronizationInfoIsSet;
  AccessNetworkId m_AnId;
  bool m_AnIdIsSet;
};

}  // namespace model
}  // namespace udm
}  // namespace oai

#endif /* HssAuthenticationInfoRequest_H_ */
