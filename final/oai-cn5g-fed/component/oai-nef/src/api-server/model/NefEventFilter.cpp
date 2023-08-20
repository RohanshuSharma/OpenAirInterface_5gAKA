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

#include "NefEventFilter.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

NefEventFilter::NefEventFilter() {
  m_AppIdsIsSet  = false;
  m_LocAreaIsSet = false;
}

void NefEventFilter::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool NefEventFilter::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool NefEventFilter::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "NefEventFilter" : pathPrefix;

  if (appIdsIsSet()) {
    const std::vector<std::string>& value = m_AppIds;
    const std::string currentValuePath    = _pathPrefix + ".appIds";

    if (value.size() < 1) {
      success = false;
      msg << currentValuePath << ": must have at least 1 elements;";
    }
    {  // Recursive validation of array elements
      const std::string oldValuePath = currentValuePath;
      int i                          = 0;
      for (const std::string& value : value) {
        const std::string currentValuePath =
            oldValuePath + "[" + std::to_string(i) + "]";

        i++;
      }
    }
  }

  return success;
}

bool NefEventFilter::operator==(const NefEventFilter& rhs) const {
  return

      (getTgtUe() == rhs.getTgtUe()) &&

      ((!appIdsIsSet() && !rhs.appIdsIsSet()) ||
       (appIdsIsSet() && rhs.appIdsIsSet() &&
        getAppIds() == rhs.getAppIds())) &&

      ((!locAreaIsSet() && !rhs.locAreaIsSet()) ||
       (locAreaIsSet() && rhs.locAreaIsSet() &&
        getLocArea() == rhs.getLocArea()))

          ;
}

bool NefEventFilter::operator!=(const NefEventFilter& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const NefEventFilter& o) {
  j          = nlohmann::json();
  j["tgtUe"] = o.m_TgtUe;
  if (o.appIdsIsSet() || !o.m_AppIds.empty()) j["appIds"] = o.m_AppIds;
  if (o.locAreaIsSet()) j["locArea"] = o.m_LocArea;
}

void from_json(const nlohmann::json& j, NefEventFilter& o) {
  j.at("tgtUe").get_to(o.m_TgtUe);
  if (j.find("appIds") != j.end()) {
    j.at("appIds").get_to(o.m_AppIds);
    o.m_AppIdsIsSet = true;
  }
  if (j.find("locArea") != j.end()) {
    j.at("locArea").get_to(o.m_LocArea);
    o.m_LocAreaIsSet = true;
  }
}

TargetUeIdentification NefEventFilter::getTgtUe() const {
  return m_TgtUe;
}
void NefEventFilter::setTgtUe(TargetUeIdentification const& value) {
  m_TgtUe = value;
}
std::vector<std::string> NefEventFilter::getAppIds() const {
  return m_AppIds;
}
void NefEventFilter::setAppIds(std::vector<std::string> const& value) {
  m_AppIds      = value;
  m_AppIdsIsSet = true;
}
bool NefEventFilter::appIdsIsSet() const {
  return m_AppIdsIsSet;
}
void NefEventFilter::unsetAppIds() {
  m_AppIdsIsSet = false;
}
NetworkAreaInfo NefEventFilter::getLocArea() const {
  return m_LocArea;
}
void NefEventFilter::setLocArea(NetworkAreaInfo const& value) {
  m_LocArea      = value;
  m_LocAreaIsSet = true;
}
bool NefEventFilter::locAreaIsSet() const {
  return m_LocAreaIsSet;
}
void NefEventFilter::unsetLocArea() {
  m_LocAreaIsSet = false;
}

}  // namespace oai::nef::model