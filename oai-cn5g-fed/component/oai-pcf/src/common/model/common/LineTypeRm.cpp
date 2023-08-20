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

#include "LineTypeRm.h"
#include "Helpers.h"

#include <sstream>

namespace oai::model::common {

LineTypeRm::LineTypeRm() {}

bool LineTypeRm::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "LineTypeRm" : pathPrefix;

  return success;
}

void to_json(nlohmann::json& j, const LineTypeRm& o) {
  j = nlohmann::json();

  if (o.m_value.getValue() ==
      LineType_anyOf::eLineType_anyOf::INVALID_VALUE_OPENAPI_GENERATED) {
    j = nullptr;
  } else {
    to_json(j, o.m_value);
  }
}

void from_json(const nlohmann::json& j, LineTypeRm& o) {
  if (j.is_null()) {
    o.setEnumValue(
        LineType_anyOf::eLineType_anyOf::INVALID_VALUE_OPENAPI_GENERATED);
  } else {
    from_json(j, o.m_value);
  }
}

}  // namespace oai::model::common
