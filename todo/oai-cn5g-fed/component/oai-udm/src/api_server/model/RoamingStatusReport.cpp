/**
 * Nudm_EE
 * Nudm Event Exposure Service. © 2021, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.2.0-alpha.3
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "RoamingStatusReport.h"
#include "Helpers.h"

#include <sstream>

namespace oai::udm::model {

RoamingStatusReport::RoamingStatusReport() {
  m_Roaming = false;
}

void RoamingStatusReport::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::udm::helpers::ValidationException(msg.str());
  }
}

bool RoamingStatusReport::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool RoamingStatusReport::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "RoamingStatusReport" : pathPrefix;

  return success;
}

bool RoamingStatusReport::operator==(const RoamingStatusReport& rhs) const {
  return true;  // TODO
  /*


  (isRoaming() == rhs.isRoaming())
   &&

  (getNewServingPlmn() == rhs.getNewServingPlmn())


  ;

  */
}

bool RoamingStatusReport::operator!=(const RoamingStatusReport& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const RoamingStatusReport& o) {
  j                   = nlohmann::json();
  j["roaming"]        = o.m_Roaming;
  j["newServingPlmn"] = o.m_NewServingPlmn;
}

void from_json(const nlohmann::json& j, RoamingStatusReport& o) {
  j.at("roaming").get_to(o.m_Roaming);
  j.at("newServingPlmn").get_to(o.m_NewServingPlmn);
}

bool RoamingStatusReport::isRoaming() const {
  return m_Roaming;
}
void RoamingStatusReport::setRoaming(bool const value) {
  m_Roaming = value;
}
PlmnId RoamingStatusReport::getNewServingPlmn() const {
  return m_NewServingPlmn;
}
void RoamingStatusReport::setNewServingPlmn(PlmnId const& value) {
  m_NewServingPlmn = value;
}

}  // namespace oai::udm::model
