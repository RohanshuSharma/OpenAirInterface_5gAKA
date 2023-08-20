/**
 * 3gpp-analyticsexposure
 * API for Analytics Exposure. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.3
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "AnalyticsFailureCode.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

AnalyticsFailureCode::AnalyticsFailureCode() {}

void AnalyticsFailureCode::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool AnalyticsFailureCode::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool AnalyticsFailureCode::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "AnalyticsFailureCode" : pathPrefix;

  if (!m_value.validate(msg)) {
    success = false;
  }
  return success;
}

bool AnalyticsFailureCode::operator==(const AnalyticsFailureCode& rhs) const {
  return

      getValue() == rhs.getValue();
}

bool AnalyticsFailureCode::operator!=(const AnalyticsFailureCode& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AnalyticsFailureCode& o) {
  j = nlohmann::json();
  to_json(j, o.m_value);
}

void from_json(const nlohmann::json& j, AnalyticsFailureCode& o) {
  from_json(j, o.m_value);
}

AnalyticsFailureCode_anyOf AnalyticsFailureCode::getValue() const {
  return m_value;
}

void AnalyticsFailureCode::setValue(AnalyticsFailureCode_anyOf value) {
  m_value = value;
}

AnalyticsFailureCode_anyOf::eAnalyticsFailureCode_anyOf
AnalyticsFailureCode::getEnumValue() const {
  return m_value.getValue();
}

void AnalyticsFailureCode::setEnumValue(
    AnalyticsFailureCode_anyOf::eAnalyticsFailureCode_anyOf value) {
  m_value.setValue(value);
}

}  // namespace oai::nef::model
