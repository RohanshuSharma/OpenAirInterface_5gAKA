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
 * FlowStatus.h
 *
 *
 */

#ifndef FlowStatus_H_
#define FlowStatus_H_

#include "FlowStatus_anyOf.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace pcf {
namespace model {

/// <summary>
///
/// </summary>
class FlowStatus {
 public:
  FlowStatus();
  virtual ~FlowStatus() = default;

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

  bool operator==(const FlowStatus& rhs) const;
  bool operator!=(const FlowStatus& rhs) const;

  /////////////////////////////////////////////
  /// FlowStatus members

  FlowStatus_anyOf getValue() const;
  void setValue(FlowStatus_anyOf value);
  FlowStatus_anyOf::eFlowStatus_anyOf getEnumValue() const;
  void setEnumValue(FlowStatus_anyOf::eFlowStatus_anyOf value);
  friend void to_json(nlohmann::json& j, const FlowStatus& o);
  friend void from_json(const nlohmann::json& j, FlowStatus& o);
  friend void to_json(nlohmann::json& j, const FlowStatus_anyOf& o);
  friend void from_json(const nlohmann::json& j, FlowStatus_anyOf& o);

 protected:
  FlowStatus_anyOf m_value;
};

}  // namespace model
}  // namespace pcf
}  // namespace oai
#endif /* FlowStatus_H_ */
