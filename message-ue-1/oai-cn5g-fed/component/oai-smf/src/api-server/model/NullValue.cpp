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

#include "NullValue.h"
#include "Helpers.h"
#include <stdexcept>
#include <sstream>

namespace oai {
namespace smf_server {
namespace model {

NullValue::NullValue() {}

void NullValue::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    //        throw
    //        org::openapitools::server::helpers::ValidationException(msg.str());
  }
}

bool NullValue::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool NullValue::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success                  = true;
  const std::string _pathPrefix = pathPrefix.empty() ? "NullValue" : pathPrefix;

  if (m_value == NullValue::eNullValue::INVALID_VALUE_OPENAPI_GENERATED) {
    success = false;
    msg << _pathPrefix << ": has no value;";
  }

  return success;
}

bool NullValue::operator==(const NullValue& rhs) const {
  return getValue() == rhs.getValue()

      ;
}

bool NullValue::operator!=(const NullValue& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const NullValue& o) {
  j = nlohmann::json();

  switch (o.getValue()) {
    case NullValue::eNullValue::INVALID_VALUE_OPENAPI_GENERATED:
      j = "INVALID_VALUE_OPENAPI_GENERATED";
      break;
    case NullValue::eNullValue::NONE:
      j = "null";
      break;
  }
}

void from_json(const nlohmann::json& j, NullValue& o) {
  auto s = j.get<std::string>();
  if (s == "null") {
    o.setValue(NullValue::eNullValue::NONE);
  } else {
    std::stringstream ss;
    ss << "Unexpected value " << s << " in json"
       << " cannot be converted to enum of type"
       << " NullValue::eNullValue";
    throw std::invalid_argument(ss.str());
  }
}

NullValue::eNullValue NullValue::getValue() const {
  return m_value;
}
void NullValue::setValue(NullValue::eNullValue value) {
  m_value = value;
}

}  // namespace model
}  // namespace smf_server
}  // namespace oai