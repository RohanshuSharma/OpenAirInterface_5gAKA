/**
 * Namf_EventExposure
 * AMF Event Exposure Service © 2022, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.7
 *
 * NOTE: This class is auto generated by OpenAPI-Generator 6.0.1.
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

#include "LossOfConnectivityReason.h"
#include "Helpers.h"

#include <sstream>

namespace oai::amf::model {

LossOfConnectivityReason::LossOfConnectivityReason() {}

void LossOfConnectivityReason::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::amf::helpers::ValidationException(msg.str());
  }
}

bool LossOfConnectivityReason::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool LossOfConnectivityReason::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "LossOfConnectivityReason" : pathPrefix;

  return success;
}

bool LossOfConnectivityReason::operator==(
    const LossOfConnectivityReason& rhs) const {
  return true;  // TODO

  ;
}

bool LossOfConnectivityReason::operator!=(
    const LossOfConnectivityReason& rhs) const {
  return !(*this == rhs);
}

void LossOfConnectivityReason::set_value(std::string value) {
  this->value = value;
}
void LossOfConnectivityReason::get_value(std::string& value) const {
  value = this->value;
}
std::string LossOfConnectivityReason::get_value() const {
  return value;
}

void to_json(nlohmann::json& j, const LossOfConnectivityReason& o) {
  j = o.get_value();
}

void from_json(const nlohmann::json& j, LossOfConnectivityReason& o) {
  o.set_value(j.get<std::string>());
}

}  // namespace oai::amf::model