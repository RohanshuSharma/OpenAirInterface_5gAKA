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

#include "CommunicationCollection.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

CommunicationCollection::CommunicationCollection() {
  m_StartTime = "";
  m_EndTime   = "";
  m_UlVol     = 0L;
  m_DlVol     = 0L;
}

void CommunicationCollection::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool CommunicationCollection::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool CommunicationCollection::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "CommunicationCollection" : pathPrefix;

  /* UlVol */ {
    const int64_t& value               = m_UlVol;
    const std::string currentValuePath = _pathPrefix + ".ulVol";

    if (value < 0ll) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
  }

  /* DlVol */ {
    const int64_t& value               = m_DlVol;
    const std::string currentValuePath = _pathPrefix + ".dlVol";

    if (value < 0ll) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
  }

  return success;
}

bool CommunicationCollection::operator==(
    const CommunicationCollection& rhs) const {
  return

      (getStartTime() == rhs.getStartTime()) &&

      (getEndTime() == rhs.getEndTime()) &&

      (getUlVol() == rhs.getUlVol()) &&

      (getDlVol() == rhs.getDlVol())

          ;
}

bool CommunicationCollection::operator!=(
    const CommunicationCollection& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const CommunicationCollection& o) {
  j              = nlohmann::json();
  j["startTime"] = o.m_StartTime;
  j["endTime"]   = o.m_EndTime;
  j["ulVol"]     = o.m_UlVol;
  j["dlVol"]     = o.m_DlVol;
}

void from_json(const nlohmann::json& j, CommunicationCollection& o) {
  j.at("startTime").get_to(o.m_StartTime);
  j.at("endTime").get_to(o.m_EndTime);
  j.at("ulVol").get_to(o.m_UlVol);
  j.at("dlVol").get_to(o.m_DlVol);
}

std::string CommunicationCollection::getStartTime() const {
  return m_StartTime;
}
void CommunicationCollection::setStartTime(std::string const& value) {
  m_StartTime = value;
}
std::string CommunicationCollection::getEndTime() const {
  return m_EndTime;
}
void CommunicationCollection::setEndTime(std::string const& value) {
  m_EndTime = value;
}
int64_t CommunicationCollection::getUlVol() const {
  return m_UlVol;
}
void CommunicationCollection::setUlVol(int64_t const value) {
  m_UlVol = value;
}
int64_t CommunicationCollection::getDlVol() const {
  return m_DlVol;
}
void CommunicationCollection::setDlVol(int64_t const value) {
  m_DlVol = value;
}

}  // namespace oai::nef::model
