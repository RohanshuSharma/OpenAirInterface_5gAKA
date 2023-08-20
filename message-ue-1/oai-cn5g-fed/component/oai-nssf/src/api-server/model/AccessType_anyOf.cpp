/**
 * NSSF NS Selection
 * NSSF Network Slice Selection Service. © 2021, 3GPP Organizational Partners
 * (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 2.1.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "AccessType_anyOf.h"
#include "Helpers.h"
#include <sstream>
#include <stdexcept>

namespace oai {
namespace nssf_server {
namespace model {

AccessType_anyOf::AccessType_anyOf() {}

void AccessType_anyOf::validate() const {
  std::stringstream msg;
  // if (!validate(msg))
  // {
  //     throw oai::nssf_server::helpers::ValidationException(msg.str());
  // }
}

bool AccessType_anyOf::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool AccessType_anyOf::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "AccessType_anyOf" : pathPrefix;

  if (m_value ==
      AccessType_anyOf::eAccessType_anyOf::INVALID_VALUE_OPENAPI_GENERATED) {
    success = false;
    msg << _pathPrefix << ": has no value;";
  }

  return success;
}

bool AccessType_anyOf::operator==(const AccessType_anyOf& rhs) const {
  return getValue() == rhs.getValue()

      ;
}

bool AccessType_anyOf::operator!=(const AccessType_anyOf& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AccessType_anyOf& o) {
  j = nlohmann::json();

  switch (o.getValue()) {
    case AccessType_anyOf::eAccessType_anyOf::INVALID_VALUE_OPENAPI_GENERATED:
      j = "INVALID_VALUE_OPENAPI_GENERATED";
      break;
    case AccessType_anyOf::eAccessType_anyOf::ACCESS_3GPP:
      j = "3GPP_ACCESS";
      break;
    case AccessType_anyOf::eAccessType_anyOf::ACCESS_NON_3GPP:
      j = "NON_3GPP_ACCESS";
      break;
  }
}

void from_json(const nlohmann::json& j, AccessType_anyOf& o) {
  auto s = j.get<std::string>();
  if (s == "3GPP_ACCESS") {
    o.setValue(AccessType_anyOf::eAccessType_anyOf::ACCESS_3GPP);
  } else if (s == "NON_3GPP_ACCESS") {
    o.setValue(AccessType_anyOf::eAccessType_anyOf::ACCESS_NON_3GPP);
  } else {
    std::stringstream ss;
    ss << "Unexpected value " << s << " in json"
       << " cannot be converted to enum of type"
       << " AccessType_anyOf::eAccessType_anyOf";
    throw std::invalid_argument(ss.str());
  }
}

AccessType_anyOf::eAccessType_anyOf AccessType_anyOf::getValue() const {
  return m_value;
}
void AccessType_anyOf::setValue(AccessType_anyOf::eAccessType_anyOf value) {
  m_value = value;
}

}  // namespace model
}  // namespace nssf_server
}  // namespace oai