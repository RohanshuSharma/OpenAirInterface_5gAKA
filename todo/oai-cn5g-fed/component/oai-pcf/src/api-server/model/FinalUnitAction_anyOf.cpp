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

#include "FinalUnitAction_anyOf.h"
#include "Helpers.h"
#include <stdexcept>
#include <sstream>

namespace oai {
namespace pcf {
namespace model {

FinalUnitAction_anyOf::FinalUnitAction_anyOf() {}

void FinalUnitAction_anyOf::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    //        throw
    //        org::openapitools::server::helpers::ValidationException(msg.str());
  }
}

bool FinalUnitAction_anyOf::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool FinalUnitAction_anyOf::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "FinalUnitAction_anyOf" : pathPrefix;

  if (m_value == FinalUnitAction_anyOf::eFinalUnitAction_anyOf::
                     INVALID_VALUE_OPENAPI_GENERATED) {
    success = false;
    msg << _pathPrefix << ": has no value;";
  }

  return success;
}

bool FinalUnitAction_anyOf::operator==(const FinalUnitAction_anyOf& rhs) const {
  return getValue() == rhs.getValue()

      ;
}

bool FinalUnitAction_anyOf::operator!=(const FinalUnitAction_anyOf& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const FinalUnitAction_anyOf& o) {
  j = nlohmann::json();

  switch (o.getValue()) {
    case FinalUnitAction_anyOf::eFinalUnitAction_anyOf::
        INVALID_VALUE_OPENAPI_GENERATED:
      j = "INVALID_VALUE_OPENAPI_GENERATED";
      break;
    case FinalUnitAction_anyOf::eFinalUnitAction_anyOf::TERMINATE:
      j = "TERMINATE";
      break;
    case FinalUnitAction_anyOf::eFinalUnitAction_anyOf::REDIRECT:
      j = "REDIRECT";
      break;
    case FinalUnitAction_anyOf::eFinalUnitAction_anyOf::RESTRICT_ACCESS:
      j = "RESTRICT_ACCESS";
      break;
  }
}

void from_json(const nlohmann::json& j, FinalUnitAction_anyOf& o) {
  auto s = j.get<std::string>();
  if (s == "TERMINATE") {
    o.setValue(FinalUnitAction_anyOf::eFinalUnitAction_anyOf::TERMINATE);
  } else if (s == "REDIRECT") {
    o.setValue(FinalUnitAction_anyOf::eFinalUnitAction_anyOf::REDIRECT);
  } else if (s == "RESTRICT_ACCESS") {
    o.setValue(FinalUnitAction_anyOf::eFinalUnitAction_anyOf::RESTRICT_ACCESS);
  } else {
    std::stringstream ss;
    ss << "Unexpected value " << s << " in json"
       << " cannot be converted to enum of type"
       << " FinalUnitAction_anyOf::eFinalUnitAction_anyOf";
    throw std::invalid_argument(ss.str());
  }
}

FinalUnitAction_anyOf::eFinalUnitAction_anyOf FinalUnitAction_anyOf::getValue()
    const {
  return m_value;
}
void FinalUnitAction_anyOf::setValue(
    FinalUnitAction_anyOf::eFinalUnitAction_anyOf value) {
  m_value = value;
}

}  // namespace model
}  // namespace pcf
}  // namespace oai
