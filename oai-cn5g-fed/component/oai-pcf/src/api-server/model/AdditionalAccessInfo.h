/**
 * Npcf_SMPolicyControl API
 * Session Management Policy Control Service © 2020, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.1.alpha-5
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * AdditionalAccessInfo.h
 *
 *
 */

#ifndef AdditionalAccessInfo_H_
#define AdditionalAccessInfo_H_

#include "RatType.h"
#include "AccessType.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace pcf {
namespace model {

/// <summary>
///
/// </summary>
class AdditionalAccessInfo {
 public:
  AdditionalAccessInfo();
  virtual ~AdditionalAccessInfo() = default;

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

  bool operator==(const AdditionalAccessInfo& rhs) const;
  bool operator!=(const AdditionalAccessInfo& rhs) const;

  /////////////////////////////////////////////
  /// AdditionalAccessInfo members

  /// <summary>
  ///
  /// </summary>
  oai::model::common::AccessType getAccessType() const;
  void setAccessType(oai::model::common::AccessType const& value);
  /// <summary>
  ///
  /// </summary>
  oai::model::common::RatType getRatType() const;
  void setRatType(oai::model::common::RatType const& value);
  bool ratTypeIsSet() const;
  void unsetRatType();

  friend void to_json(nlohmann::json& j, const AdditionalAccessInfo& o);
  friend void from_json(const nlohmann::json& j, AdditionalAccessInfo& o);

 protected:
  oai::model::common::AccessType m_AccessType;

  oai::model::common::RatType m_RatType;
  bool m_RatTypeIsSet;
};

}  // namespace model
}  // namespace pcf
}  // namespace oai
#endif /* AdditionalAccessInfo_H_ */