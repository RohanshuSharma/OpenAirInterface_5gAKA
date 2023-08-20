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

#include "LocationFailureCause_anyOf.h"

#include <sstream>
#include <stdexcept>

#include "Helpers.h"

namespace oai::nef::model {

LocationFailureCause_anyOf::LocationFailureCause_anyOf() {}

void LocationFailureCause_anyOf::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool LocationFailureCause_anyOf::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool LocationFailureCause_anyOf::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "LocationFailureCause_anyOf" : pathPrefix;

  if (m_value == LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
                     INVALID_VALUE_OPENAPI_GENERATED) {
    success = false;
    msg << _pathPrefix << ": has no value;";
  }

  return success;
}

bool LocationFailureCause_anyOf::operator==(
    const LocationFailureCause_anyOf& rhs) const {
  return getValue() == rhs.getValue()

      ;
}

bool LocationFailureCause_anyOf::operator!=(
    const LocationFailureCause_anyOf& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const LocationFailureCause_anyOf& o) {
  j = nlohmann::json();

  switch (o.getValue()) {
    case LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
        INVALID_VALUE_OPENAPI_GENERATED:
      j = "INVALID_VALUE_OPENAPI_GENERATED";
      break;
    case LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
        POSITIONING_DENIED:
      j = "POSITIONING_DENIED";
      break;
    case LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
        UNSUPPORTED_BY_UE:
      j = "UNSUPPORTED_BY_UE";
      break;
    case LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
        NOT_REGISTED_UE:
      j = "NOT_REGISTED_UE";
      break;
    case LocationFailureCause_anyOf::eLocationFailureCause_anyOf::UNSPECIFIED:
      j = "UNSPECIFIED";
      break;
  }
}

void from_json(const nlohmann::json& j, LocationFailureCause_anyOf& o) {
  auto s = j.get<std::string>();
  if (s == "POSITIONING_DENIED") {
    o.setValue(LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
                   POSITIONING_DENIED);
  } else if (s == "UNSUPPORTED_BY_UE") {
    o.setValue(LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
                   UNSUPPORTED_BY_UE);
  } else if (s == "NOT_REGISTED_UE") {
    o.setValue(LocationFailureCause_anyOf::eLocationFailureCause_anyOf::
                   NOT_REGISTED_UE);
  } else if (s == "UNSPECIFIED") {
    o.setValue(
        LocationFailureCause_anyOf::eLocationFailureCause_anyOf::UNSPECIFIED);
  } else {
    std::stringstream ss;
    ss << "Unexpected value " << s << " in json"
       << " cannot be converted to enum of type"
       << " LocationFailureCause_anyOf::eLocationFailureCause_anyOf";
    throw std::invalid_argument(ss.str());
  }
}

LocationFailureCause_anyOf::eLocationFailureCause_anyOf
LocationFailureCause_anyOf::getValue() const {
  return m_value;
}
void LocationFailureCause_anyOf::setValue(
    LocationFailureCause_anyOf::eLocationFailureCause_anyOf value) {
  m_value = value;
}

}  // namespace oai::nef::model
