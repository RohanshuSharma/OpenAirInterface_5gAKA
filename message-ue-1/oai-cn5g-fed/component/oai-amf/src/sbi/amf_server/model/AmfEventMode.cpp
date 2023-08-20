/**
 * Namf_EventExposure
 * AMF Event Exposure Service © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "AmfEventMode.h"
#include "Helpers.h"

#include <sstream>

namespace oai::amf::model {

AmfEventMode::AmfEventMode() {
  m_MaxReports      = 0;
  m_MaxReportsIsSet = false;
  m_Expiry          = "";
  m_ExpiryIsSet     = false;
}

void AmfEventMode::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::amf::helpers::ValidationException(msg.str());
  }
}

bool AmfEventMode::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool AmfEventMode::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "AmfEventMode" : pathPrefix;

  return success;
}

bool AmfEventMode::operator==(const AmfEventMode& rhs) const {
  return

      (getTrigger() == rhs.getTrigger()) &&

      ((!maxReportsIsSet() && !rhs.maxReportsIsSet()) ||
       (maxReportsIsSet() && rhs.maxReportsIsSet() &&
        getMaxReports() == rhs.getMaxReports())) &&

      ((!expiryIsSet() && !rhs.expiryIsSet()) ||
       (expiryIsSet() && rhs.expiryIsSet() && getExpiry() == rhs.getExpiry()))

          ;
}

bool AmfEventMode::operator!=(const AmfEventMode& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AmfEventMode& o) {
  j            = nlohmann::json();
  j["trigger"] = o.m_Trigger;
  if (o.maxReportsIsSet()) j["maxReports"] = o.m_MaxReports;
  if (o.expiryIsSet()) j["expiry"] = o.m_Expiry;
}

void from_json(const nlohmann::json& j, AmfEventMode& o) {
  j.at("trigger").get_to(o.m_Trigger);
  if (j.find("maxReports") != j.end()) {
    j.at("maxReports").get_to(o.m_MaxReports);
    o.m_MaxReportsIsSet = true;
  }
  if (j.find("expiry") != j.end()) {
    j.at("expiry").get_to(o.m_Expiry);
    o.m_ExpiryIsSet = true;
  }
}

AmfEventTrigger AmfEventMode::getTrigger() const {
  return m_Trigger;
}
void AmfEventMode::setTrigger(AmfEventTrigger const& value) {
  m_Trigger = value;
}
int32_t AmfEventMode::getMaxReports() const {
  return m_MaxReports;
}
void AmfEventMode::setMaxReports(int32_t const value) {
  m_MaxReports      = value;
  m_MaxReportsIsSet = true;
}
bool AmfEventMode::maxReportsIsSet() const {
  return m_MaxReportsIsSet;
}
void AmfEventMode::unsetMaxReports() {
  m_MaxReportsIsSet = false;
}
std::string AmfEventMode::getExpiry() const {
  return m_Expiry;
}
void AmfEventMode::setExpiry(std::string const& value) {
  m_Expiry      = value;
  m_ExpiryIsSet = true;
}
bool AmfEventMode::expiryIsSet() const {
  return m_ExpiryIsSet;
}
void AmfEventMode::unsetExpiry() {
  m_ExpiryIsSet = false;
}

}  // namespace oai::amf::model
