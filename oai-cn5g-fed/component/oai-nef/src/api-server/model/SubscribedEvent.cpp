/**
 * 3gpp-traffic-influence
 * API for AF traffic influence © 2021, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "SubscribedEvent.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

SubscribedEvent::SubscribedEvent() {}

void SubscribedEvent::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool SubscribedEvent::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool SubscribedEvent::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "SubscribedEvent" : pathPrefix;

  if (!m_value.validate(msg)) {
    success = false;
  }
  return success;
}

bool SubscribedEvent::operator==(const SubscribedEvent& rhs) const {
  return

      getValue() == rhs.getValue();
}

bool SubscribedEvent::operator!=(const SubscribedEvent& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const SubscribedEvent& o) {
  j = nlohmann::json();
  to_json(j, o.m_value);
}

void from_json(const nlohmann::json& j, SubscribedEvent& o) {
  from_json(j, o.m_value);
}

SubscribedEvent_anyOf SubscribedEvent::getValue() const {
  return m_value;
}

void SubscribedEvent::setValue(SubscribedEvent_anyOf value) {
  m_value = value;
}

SubscribedEvent_anyOf::eSubscribedEvent_anyOf SubscribedEvent::getEnumValue()
    const {
  return m_value.getValue();
}

void SubscribedEvent::setEnumValue(
    SubscribedEvent_anyOf::eSubscribedEvent_anyOf value) {
  m_value.setValue(value);
}

}  // namespace oai::nef::model