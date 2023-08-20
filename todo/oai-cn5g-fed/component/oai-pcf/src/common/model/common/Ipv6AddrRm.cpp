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

#include "Ipv6AddrRm.h"
#include "Helpers.h"

#include <sstream>

namespace oai::model::common {

Ipv6AddrRm::Ipv6AddrRm() {}

bool Ipv6AddrRm::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "Ipv6AddrRm" : pathPrefix;

  return success;
}

void to_json(nlohmann::json& j, const Ipv6AddrRm& o) {
  j = nlohmann::json();
  if (o.m_Ipv6Addr.empty()) {
    j = nullptr;
  } else {
    j = o.m_Ipv6Addr;
  }
}

void from_json(const nlohmann::json& j, Ipv6AddrRm& o) {
  if (!j.is_null()) {
    o.setIpv6Addr(j);
  }
}

}  // namespace oai::model::common
