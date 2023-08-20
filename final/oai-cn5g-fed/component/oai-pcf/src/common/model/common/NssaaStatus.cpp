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

#include "NssaaStatus.h"
#include "Helpers.h"

#include <sstream>

namespace oai::model::common {

NssaaStatus::NssaaStatus() {}

void NssaaStatus::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::model::common::helpers::ValidationException(msg.str());
  }
}

bool NssaaStatus::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool NssaaStatus::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "NssaaStatus" : pathPrefix;

  return success;
}

bool NssaaStatus::operator==(const NssaaStatus& rhs) const {
  return

      (getSnssai() == rhs.getSnssai()) &&

      (getStatus() == rhs.getStatus())

          ;
}

bool NssaaStatus::operator!=(const NssaaStatus& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const NssaaStatus& o) {
  j           = nlohmann::json();
  j["snssai"] = o.m_Snssai;
  j["status"] = o.m_Status;
}

void from_json(const nlohmann::json& j, NssaaStatus& o) {
  j.at("snssai").get_to(o.m_Snssai);
  j.at("status").get_to(o.m_Status);
}

oai::model::common::Snssai NssaaStatus::getSnssai() const {
  return m_Snssai;
}
void NssaaStatus::setSnssai(oai::model::common::Snssai const& value) {
  m_Snssai = value;
}
oai::model::common::AuthStatus NssaaStatus::getStatus() const {
  return m_Status;
}
void NssaaStatus::setStatus(oai::model::common::AuthStatus const& value) {
  m_Status = value;
}

}  // namespace oai::model::common