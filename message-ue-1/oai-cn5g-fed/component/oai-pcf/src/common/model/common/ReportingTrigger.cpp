/**
 * Common Data Types
 * Common Data Types for Service Based Interfaces. © 2020, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.2.1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "ReportingTrigger.h"
#include "Helpers.h"

#include <sstream>

namespace oai::model::common {

ReportingTrigger::ReportingTrigger() {}

void ReportingTrigger::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::model::common::helpers::ValidationException(msg.str());
  }
}

bool ReportingTrigger::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool ReportingTrigger::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "ReportingTrigger" : pathPrefix;

  if (!m_value.validate(msg)) {
    success = false;
  }
  return success;
}

bool ReportingTrigger::operator==(const ReportingTrigger& rhs) const {
  return

      getValue() == rhs.getValue();
}

bool ReportingTrigger::operator!=(const ReportingTrigger& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ReportingTrigger& o) {
  j = nlohmann::json();
  to_json(j, o.m_value);
}

void from_json(const nlohmann::json& j, ReportingTrigger& o) {
  from_json(j, o.m_value);
}

ReportingTrigger_anyOf ReportingTrigger::getValue() const {
  return m_value;
}

void ReportingTrigger::setValue(ReportingTrigger_anyOf value) {
  m_value = value;
}

ReportingTrigger_anyOf::eReportingTrigger_anyOf ReportingTrigger::getEnumValue()
    const {
  return m_value.getValue();
}

void ReportingTrigger::setEnumValue(
    ReportingTrigger_anyOf::eReportingTrigger_anyOf value) {
  m_value.setValue(value);
}

}  // namespace oai::model::common
