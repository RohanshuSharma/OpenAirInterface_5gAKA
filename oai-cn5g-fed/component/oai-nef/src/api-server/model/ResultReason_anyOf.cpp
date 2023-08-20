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

#include "ResultReason_anyOf.h"

#include <sstream>
#include <stdexcept>

#include "Helpers.h"

namespace oai::nef::model {

ResultReason_anyOf::ResultReason_anyOf() {}

void ResultReason_anyOf::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool ResultReason_anyOf::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool ResultReason_anyOf::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "ResultReason_anyOf" : pathPrefix;

  if (m_value == ResultReason_anyOf::eResultReason_anyOf::
                     INVALID_VALUE_OPENAPI_GENERATED) {
    success = false;
    msg << _pathPrefix << ": has no value;";
  }

  return success;
}

bool ResultReason_anyOf::operator==(const ResultReason_anyOf& rhs) const {
  return getValue() == rhs.getValue()

      ;
}

bool ResultReason_anyOf::operator!=(const ResultReason_anyOf& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const ResultReason_anyOf& o) {
  j = nlohmann::json();

  switch (o.getValue()) {
    case ResultReason_anyOf::eResultReason_anyOf::
        INVALID_VALUE_OPENAPI_GENERATED:
      j = "INVALID_VALUE_OPENAPI_GENERATED";
      break;
    case ResultReason_anyOf::eResultReason_anyOf::ROAMING_NOT_ALLOWED:
      j = "ROAMING_NOT_ALLOWED";
      break;
    case ResultReason_anyOf::eResultReason_anyOf::OTHER_REASON:
      j = "OTHER_REASON";
      break;
  }
}

void from_json(const nlohmann::json& j, ResultReason_anyOf& o) {
  auto s = j.get<std::string>();
  if (s == "ROAMING_NOT_ALLOWED") {
    o.setValue(ResultReason_anyOf::eResultReason_anyOf::ROAMING_NOT_ALLOWED);
  } else if (s == "OTHER_REASON") {
    o.setValue(ResultReason_anyOf::eResultReason_anyOf::OTHER_REASON);
  } else {
    std::stringstream ss;
    ss << "Unexpected value " << s << " in json"
       << " cannot be converted to enum of type"
       << " ResultReason_anyOf::eResultReason_anyOf";
    throw std::invalid_argument(ss.str());
  }
}

ResultReason_anyOf::eResultReason_anyOf ResultReason_anyOf::getValue() const {
  return m_value;
}
void ResultReason_anyOf::setValue(
    ResultReason_anyOf::eResultReason_anyOf value) {
  m_value = value;
}

}  // namespace oai::nef::model