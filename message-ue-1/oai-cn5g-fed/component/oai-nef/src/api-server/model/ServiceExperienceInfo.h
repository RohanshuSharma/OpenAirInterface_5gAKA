/**
 * Nnef_EventExposure
 * NEF Event Exposure Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.5
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * ServiceExperienceInfo.h
 *
 *
 */

#ifndef ServiceExperienceInfo_H_
#define ServiceExperienceInfo_H_

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "ServiceExperienceInfoPerFlow.h"

namespace oai::nef::model {

/// <summary>
///
/// </summary>
class ServiceExperienceInfo {
 public:
  ServiceExperienceInfo();
  virtual ~ServiceExperienceInfo() = default;

  /// <summary>
  /// Validate the current data in the model. Throws a ValidationException on
  /// failure.
  /// </summary>
  void validate() const;

  /// <summary>
  /// Validate the current data in the model. Returns false on error and writes
  /// an error message into the given stringstream.
  /// </summary>
  bool validate(std::stringstream& msg) const;

  /// <summary>
  /// Helper overload for validate. Used when one model stores another model and
  /// calls it's validate. Not meant to be called outside that case.
  /// </summary>
  bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

  bool operator==(const ServiceExperienceInfo& rhs) const;
  bool operator!=(const ServiceExperienceInfo& rhs) const;

  /////////////////////////////////////////////
  /// ServiceExperienceInfo members

  /// <summary>
  ///
  /// </summary>
  std::string getAppId() const;
  void setAppId(std::string const& value);
  bool appIdIsSet() const;
  void unsetAppId();
  /// <summary>
  ///
  /// </summary>
  std::vector<std::string> getSupis() const;
  void setSupis(std::vector<std::string> const& value);
  bool supisIsSet() const;
  void unsetSupis();
  /// <summary>
  ///
  /// </summary>
  std::vector<ServiceExperienceInfoPerFlow> getSvcExpPerFlows() const;
  void setSvcExpPerFlows(
      std::vector<ServiceExperienceInfoPerFlow> const& value);

  friend void to_json(nlohmann::json& j, const ServiceExperienceInfo& o);
  friend void from_json(const nlohmann::json& j, ServiceExperienceInfo& o);

 protected:
  std::string m_AppId;
  bool m_AppIdIsSet;
  std::vector<std::string> m_Supis;
  bool m_SupisIsSet;
  std::vector<ServiceExperienceInfoPerFlow> m_SvcExpPerFlows;
};

}  // namespace oai::nef::model

#endif /* ServiceExperienceInfo_H_ */
