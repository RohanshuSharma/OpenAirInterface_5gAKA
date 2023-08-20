/**
 * Nnef_EventExposure
 * NEF Event Exposure Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.5
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "AmfEventArea.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

AmfEventArea::AmfEventArea() {
  m_PresenceInfoIsSet = false;
  m_LadnInfoIsSet     = false;
}

void AmfEventArea::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool AmfEventArea::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool AmfEventArea::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "AmfEventArea" : pathPrefix;

  return success;
}

bool AmfEventArea::operator==(const AmfEventArea& rhs) const {
  return

      ((!presenceInfoIsSet() && !rhs.presenceInfoIsSet()) ||
       (presenceInfoIsSet() && rhs.presenceInfoIsSet() &&
        getPresenceInfo() == rhs.getPresenceInfo())) &&

      ((!ladnInfoIsSet() && !rhs.ladnInfoIsSet()) ||
       (ladnInfoIsSet() && rhs.ladnInfoIsSet() &&
        getLadnInfo() == rhs.getLadnInfo()))

          ;
}

bool AmfEventArea::operator!=(const AmfEventArea& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AmfEventArea& o) {
  j = nlohmann::json();
  if (o.presenceInfoIsSet()) j["presenceInfo"] = o.m_PresenceInfo;
  if (o.ladnInfoIsSet()) j["ladnInfo"] = o.m_LadnInfo;
}

void from_json(const nlohmann::json& j, AmfEventArea& o) {
  if (j.find("presenceInfo") != j.end()) {
    j.at("presenceInfo").get_to(o.m_PresenceInfo);
    o.m_PresenceInfoIsSet = true;
  }
  if (j.find("ladnInfo") != j.end()) {
    j.at("ladnInfo").get_to(o.m_LadnInfo);
    o.m_LadnInfoIsSet = true;
  }
}

PresenceInfo AmfEventArea::getPresenceInfo() const {
  return m_PresenceInfo;
}
void AmfEventArea::setPresenceInfo(PresenceInfo const& value) {
  m_PresenceInfo      = value;
  m_PresenceInfoIsSet = true;
}
bool AmfEventArea::presenceInfoIsSet() const {
  return m_PresenceInfoIsSet;
}
void AmfEventArea::unsetPresenceInfo() {
  m_PresenceInfoIsSet = false;
}
LadnInfo AmfEventArea::getLadnInfo() const {
  return m_LadnInfo;
}
void AmfEventArea::setLadnInfo(LadnInfo const& value) {
  m_LadnInfo      = value;
  m_LadnInfoIsSet = true;
}
bool AmfEventArea::ladnInfoIsSet() const {
  return m_LadnInfoIsSet;
}
void AmfEventArea::unsetLadnInfo() {
  m_LadnInfoIsSet = false;
}

}  // namespace oai::nef::model
