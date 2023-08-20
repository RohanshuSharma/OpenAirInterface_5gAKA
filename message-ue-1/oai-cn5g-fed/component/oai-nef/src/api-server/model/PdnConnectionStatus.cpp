/**
 * 3gpp-monitoring-event
 * API for Monitoring Event. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.2.0-alpha.4
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "PdnConnectionStatus.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

PdnConnectionStatus::PdnConnectionStatus() {}

void PdnConnectionStatus::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool PdnConnectionStatus::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool PdnConnectionStatus::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "PdnConnectionStatus" : pathPrefix;

  if (!m_value.validate(msg)) {
    success = false;
  }
  return success;
}

bool PdnConnectionStatus::operator==(const PdnConnectionStatus& rhs) const {
  return

      getValue() == rhs.getValue();
}

bool PdnConnectionStatus::operator!=(const PdnConnectionStatus& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const PdnConnectionStatus& o) {
  j = nlohmann::json();
  to_json(j, o.m_value);
}

void from_json(const nlohmann::json& j, PdnConnectionStatus& o) {
  from_json(j, o.m_value);
}

PdnConnectionStatus_anyOf PdnConnectionStatus::getValue() const {
  return m_value;
}

void PdnConnectionStatus::setValue(PdnConnectionStatus_anyOf value) {
  m_value = value;
}

PdnConnectionStatus_anyOf::ePdnConnectionStatus_anyOf
PdnConnectionStatus::getEnumValue() const {
  return m_value.getValue();
}

void PdnConnectionStatus::setEnumValue(
    PdnConnectionStatus_anyOf::ePdnConnectionStatus_anyOf value) {
  m_value.setValue(value);
}

}  // namespace oai::nef::model
