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
/*
 * ProblemDetails.h
 *
 *
 */

#ifndef ProblemDetails_H_
#define ProblemDetails_H_

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "InvalidParam.h"

namespace oai::udr::model {

/// <summary>
///
/// </summary>
class ProblemDetails {
 public:
  ProblemDetails();
  virtual ~ProblemDetails();

  void validate();

  /////////////////////////////////////////////
  /// ProblemDetails members

  /// <summary>
  ///
  /// </summary>
  std::string getType() const;
  void setType(std::string const& value);
  bool typeIsSet() const;
  void unsetType();
  /// <summary>
  ///
  /// </summary>
  std::string getTitle() const;
  void setTitle(std::string const& value);
  bool titleIsSet() const;
  void unsetTitle();
  /// <summary>
  ///
  /// </summary>
  int32_t getStatus() const;
  void setStatus(int32_t const value);
  bool statusIsSet() const;
  void unsetStatus();
  /// <summary>
  ///
  /// </summary>
  std::string getDetail() const;
  void setDetail(std::string const& value);
  bool detailIsSet() const;
  void unsetDetail();
  /// <summary>
  ///
  /// </summary>
  std::string getInstance() const;
  void setInstance(std::string const& value);
  bool instanceIsSet() const;
  void unsetInstance();
  /// <summary>
  ///
  /// </summary>
  std::string getCause() const;
  void setCause(std::string const& value);
  bool causeIsSet() const;
  void unsetCause();
  /// <summary>
  ///
  /// </summary>
  std::vector<InvalidParam>& getInvalidParams();
  void setInvalidParams(std::vector<InvalidParam> const& value);
  bool invalidParamsIsSet() const;
  void unsetInvalidParams();
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
  std::string getTargetScp() const;
  void setTargetScp(std::string const& value);
  bool targetScpIsSet() const;
  void unsetTargetScp();

  friend void to_json(nlohmann::json& j, const ProblemDetails& o);
  friend void from_json(const nlohmann::json& j, ProblemDetails& o);

 protected:
  std::string m_Type;
  bool m_TypeIsSet;
  std::string m_Title;
  bool m_TitleIsSet;
  int32_t m_Status;
  bool m_StatusIsSet;
  std::string m_Detail;
  bool m_DetailIsSet;
  std::string m_Instance;
  bool m_InstanceIsSet;
  std::string m_Cause;
  bool m_CauseIsSet;
  std::vector<InvalidParam> m_InvalidParams;
  bool m_InvalidParamsIsSet;
  std::string m_SupportedFeatures;
  bool m_SupportedFeaturesIsSet;
  std::string m_TargetScp;
  bool m_TargetScpIsSet;
};

}  // namespace oai::udr::model

#endif /* ProblemDetails_H_ */
