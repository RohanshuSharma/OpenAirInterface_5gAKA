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

#include "LocationFailureCause.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

LocationFailureCause::LocationFailureCause() {}

void LocationFailureCause::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool LocationFailureCause::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool LocationFailureCause::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "LocationFailureCause" : pathPrefix;

  if (!m_value.validate(msg)) {
    success = false;
  }
  return success;
}

bool LocationFailureCause::operator==(const LocationFailureCause& rhs) const {
  return

      getValue() == rhs.getValue();
}

bool LocationFailureCause::operator!=(const LocationFailureCause& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const LocationFailureCause& o) {
  j = nlohmann::json();
  to_json(j, o.m_value);
}

void from_json(const nlohmann::json& j, LocationFailureCause& o) {
  from_json(j, o.m_value);
}

LocationFailureCause_anyOf LocationFailureCause::getValue() const {
  return m_value;
}

void LocationFailureCause::setValue(LocationFailureCause_anyOf value) {
  m_value = value;
}

LocationFailureCause_anyOf::eLocationFailureCause_anyOf
LocationFailureCause::getEnumValue() const {
  return m_value.getValue();
}

void LocationFailureCause::setEnumValue(
    LocationFailureCause_anyOf::eLocationFailureCause_anyOf value) {
  m_value.setValue(value);
}

}  // namespace oai::nef::model
