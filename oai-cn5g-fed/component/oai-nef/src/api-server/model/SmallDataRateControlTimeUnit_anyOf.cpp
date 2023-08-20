/**
 * Nnef_SMContext
 * Nnef SMContext Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "SmallDataRateControlTimeUnit_anyOf.h"

#include <sstream>
#include <stdexcept>

#include "Helpers.h"

namespace oai::nef::model {

SmallDataRateControlTimeUnit_anyOf::SmallDataRateControlTimeUnit_anyOf() {}

void SmallDataRateControlTimeUnit_anyOf::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool SmallDataRateControlTimeUnit_anyOf::validate(
    std::stringstream& msg) const {
  return validate(msg, "");
}

bool SmallDataRateControlTimeUnit_anyOf::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "SmallDataRateControlTimeUnit_anyOf" : pathPrefix;

  if (m_value ==
      SmallDataRateControlTimeUnit_anyOf::eSmallDataRateControlTimeUnit_anyOf::
          INVALID_VALUE_OPENAPI_GENERATED) {
    success = false;
    msg << _pathPrefix << ": has no value;";
  }

  return success;
}

bool SmallDataRateControlTimeUnit_anyOf::operator==(
    const SmallDataRateControlTimeUnit_anyOf& rhs) const {
  return getValue() == rhs.getValue()

      ;
}

bool SmallDataRateControlTimeUnit_anyOf::operator!=(
    const SmallDataRateControlTimeUnit_anyOf& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const SmallDataRateControlTimeUnit_anyOf& o) {
  j = nlohmann::json();

  switch (o.getValue()) {
    case SmallDataRateControlTimeUnit_anyOf::
        eSmallDataRateControlTimeUnit_anyOf::INVALID_VALUE_OPENAPI_GENERATED:
      j = "INVALID_VALUE_OPENAPI_GENERATED";
      break;
    case SmallDataRateControlTimeUnit_anyOf::
        eSmallDataRateControlTimeUnit_anyOf::MINUTE:
      j = "MINUTE";
      break;
    case SmallDataRateControlTimeUnit_anyOf::
        eSmallDataRateControlTimeUnit_anyOf::HOUR:
      j = "HOUR";
      break;
    case SmallDataRateControlTimeUnit_anyOf::
        eSmallDataRateControlTimeUnit_anyOf::DAY:
      j = "DAY";
      break;
    case SmallDataRateControlTimeUnit_anyOf::
        eSmallDataRateControlTimeUnit_anyOf::WEEK:
      j = "WEEK";
      break;
    case SmallDataRateControlTimeUnit_anyOf::
        eSmallDataRateControlTimeUnit_anyOf::_6MINUTES:
      j = "6MINUTES";
      break;
  }
}

void from_json(const nlohmann::json& j, SmallDataRateControlTimeUnit_anyOf& o) {
  auto s = j.get<std::string>();
  if (s == "MINUTE") {
    o.setValue(SmallDataRateControlTimeUnit_anyOf::
                   eSmallDataRateControlTimeUnit_anyOf::MINUTE);
  } else if (s == "HOUR") {
    o.setValue(SmallDataRateControlTimeUnit_anyOf::
                   eSmallDataRateControlTimeUnit_anyOf::HOUR);
  } else if (s == "DAY") {
    o.setValue(SmallDataRateControlTimeUnit_anyOf::
                   eSmallDataRateControlTimeUnit_anyOf::DAY);
  } else if (s == "WEEK") {
    o.setValue(SmallDataRateControlTimeUnit_anyOf::
                   eSmallDataRateControlTimeUnit_anyOf::WEEK);
  } else if (s == "6MINUTES") {
    o.setValue(SmallDataRateControlTimeUnit_anyOf::
                   eSmallDataRateControlTimeUnit_anyOf::_6MINUTES);
  } else {
    std::stringstream ss;
    ss << "Unexpected value " << s << " in json"
       << " cannot be converted to enum of type"
       << " SmallDataRateControlTimeUnit_anyOf::eSmallDataRateControlTimeUnit_"
          "anyOf";
    throw std::invalid_argument(ss.str());
  }
}

SmallDataRateControlTimeUnit_anyOf::eSmallDataRateControlTimeUnit_anyOf
SmallDataRateControlTimeUnit_anyOf::getValue() const {
  return m_value;
}
void SmallDataRateControlTimeUnit_anyOf::setValue(
    SmallDataRateControlTimeUnit_anyOf::eSmallDataRateControlTimeUnit_anyOf
        value) {
  m_value = value;
}

}  // namespace oai::nef::model