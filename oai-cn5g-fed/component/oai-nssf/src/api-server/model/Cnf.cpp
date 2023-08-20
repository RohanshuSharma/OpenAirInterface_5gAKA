/**
 * NRF NFDiscovery Service
 * NRF NFDiscovery Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "Cnf.h"

namespace oai {
namespace nssf_server {
namespace model {

Cnf::Cnf() {}

Cnf::~Cnf() {}

void Cnf::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const Cnf& o) {
  j             = nlohmann::json();
  j["cnfUnits"] = o.m_CnfUnits;
}

void from_json(const nlohmann::json& j, Cnf& o) {
  j.at("cnfUnits").get_to(o.m_CnfUnits);
}

std::vector<CnfUnit>& Cnf::getCnfUnits() {
  return m_CnfUnits;
}
void Cnf::setCnfUnits(std::vector<CnfUnit> const& value) {
  m_CnfUnits = value;
}

}  // namespace model
}  // namespace nssf_server
}  // namespace oai
