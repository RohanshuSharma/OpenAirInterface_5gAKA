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

#include "SteerModeValue.h"
#include "Helpers.h"

#include <sstream>

namespace oai {
namespace pcf {
namespace model {

SteerModeValue::SteerModeValue() {}

void SteerModeValue::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    //        throw
    //        org::openapitools::server::helpers::ValidationException(msg.str());
  }
}

bool SteerModeValue::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool SteerModeValue::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "SteerModeValue" : pathPrefix;

  if (!m_value.validate(msg)) {
    success = false;
  }
  return success;
}

bool SteerModeValue::operator==(const SteerModeValue& rhs) const {
  return

      getValue() == rhs.getValue();
}

bool SteerModeValue::operator!=(const SteerModeValue& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const SteerModeValue& o) {
  j = nlohmann::json();
  to_json(j, o.m_value);
}

void from_json(const nlohmann::json& j, SteerModeValue& o) {
  from_json(j, o.m_value);
}

SteerModeValue_anyOf SteerModeValue::getValue() const {
  return m_value;
}

void SteerModeValue::setValue(SteerModeValue_anyOf value) {
  m_value = value;
}

SteerModeValue_anyOf::eSteerModeValue_anyOf SteerModeValue::getEnumValue()
    const {
  return m_value.getValue();
}

void SteerModeValue::setEnumValue(
    SteerModeValue_anyOf::eSteerModeValue_anyOf value) {
  m_value.setValue(value);
}

}  // namespace model
}  // namespace pcf
}  // namespace oai
