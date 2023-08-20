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

#include "AmfEventNotification.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

AmfEventNotification::AmfEventNotification() {
  m_NotifyCorrelationId                = "";
  m_NotifyCorrelationIdIsSet           = false;
  m_SubsChangeNotifyCorrelationId      = "";
  m_SubsChangeNotifyCorrelationIdIsSet = false;
  m_ReportListIsSet                    = false;
}

void AmfEventNotification::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool AmfEventNotification::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool AmfEventNotification::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "AmfEventNotification" : pathPrefix;

  if (reportListIsSet()) {
    const std::vector<AmfEventReport>& value = m_ReportList;
    const std::string currentValuePath       = _pathPrefix + ".reportList";

    if (value.size() < 1) {
      success = false;
      msg << currentValuePath << ": must have at least 1 elements;";
    }
    {  // Recursive validation of array elements
      const std::string oldValuePath = currentValuePath;
      int i                          = 0;
      for (const AmfEventReport& value : value) {
        const std::string currentValuePath =
            oldValuePath + "[" + std::to_string(i) + "]";

        success =
            value.validate(msg, currentValuePath + ".reportList") && success;

        i++;
      }
    }
  }

  return success;
}

bool AmfEventNotification::operator==(const AmfEventNotification& rhs) const {
  return

      ((!notifyCorrelationIdIsSet() && !rhs.notifyCorrelationIdIsSet()) ||
       (notifyCorrelationIdIsSet() && rhs.notifyCorrelationIdIsSet() &&
        getNotifyCorrelationId() == rhs.getNotifyCorrelationId())) &&

      ((!subsChangeNotifyCorrelationIdIsSet() &&
        !rhs.subsChangeNotifyCorrelationIdIsSet()) ||
       (subsChangeNotifyCorrelationIdIsSet() &&
        rhs.subsChangeNotifyCorrelationIdIsSet() &&
        getSubsChangeNotifyCorrelationId() ==
            rhs.getSubsChangeNotifyCorrelationId())) &&

      ((!reportListIsSet() && !rhs.reportListIsSet()) ||
       (reportListIsSet() && rhs.reportListIsSet() &&
        getReportList() == rhs.getReportList()))

          ;
}

bool AmfEventNotification::operator!=(const AmfEventNotification& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AmfEventNotification& o) {
  j = nlohmann::json();
  if (o.notifyCorrelationIdIsSet())
    j["notifyCorrelationId"] = o.m_NotifyCorrelationId;
  if (o.subsChangeNotifyCorrelationIdIsSet())
    j["subsChangeNotifyCorrelationId"] = o.m_SubsChangeNotifyCorrelationId;
  if (o.reportListIsSet() || !o.m_ReportList.empty())
    j["reportList"] = o.m_ReportList;
}

void from_json(const nlohmann::json& j, AmfEventNotification& o) {
  if (j.find("notifyCorrelationId") != j.end()) {
    j.at("notifyCorrelationId").get_to(o.m_NotifyCorrelationId);
    o.m_NotifyCorrelationIdIsSet = true;
  }
  if (j.find("subsChangeNotifyCorrelationId") != j.end()) {
    j.at("subsChangeNotifyCorrelationId")
        .get_to(o.m_SubsChangeNotifyCorrelationId);
    o.m_SubsChangeNotifyCorrelationIdIsSet = true;
  }
  if (j.find("reportList") != j.end()) {
    j.at("reportList").get_to(o.m_ReportList);
    o.m_ReportListIsSet = true;
  }
}

std::string AmfEventNotification::getNotifyCorrelationId() const {
  return m_NotifyCorrelationId;
}
void AmfEventNotification::setNotifyCorrelationId(std::string const& value) {
  m_NotifyCorrelationId      = value;
  m_NotifyCorrelationIdIsSet = true;
}
bool AmfEventNotification::notifyCorrelationIdIsSet() const {
  return m_NotifyCorrelationIdIsSet;
}
void AmfEventNotification::unsetNotifyCorrelationId() {
  m_NotifyCorrelationIdIsSet = false;
}
std::string AmfEventNotification::getSubsChangeNotifyCorrelationId() const {
  return m_SubsChangeNotifyCorrelationId;
}
void AmfEventNotification::setSubsChangeNotifyCorrelationId(
    std::string const& value) {
  m_SubsChangeNotifyCorrelationId      = value;
  m_SubsChangeNotifyCorrelationIdIsSet = true;
}
bool AmfEventNotification::subsChangeNotifyCorrelationIdIsSet() const {
  return m_SubsChangeNotifyCorrelationIdIsSet;
}
void AmfEventNotification::unsetSubsChangeNotifyCorrelationId() {
  m_SubsChangeNotifyCorrelationIdIsSet = false;
}
std::vector<AmfEventReport> AmfEventNotification::getReportList() const {
  return m_ReportList;
}
void AmfEventNotification::setReportList(
    std::vector<AmfEventReport> const& value) {
  m_ReportList      = value;
  m_ReportListIsSet = true;
}
bool AmfEventNotification::reportListIsSet() const {
  return m_ReportListIsSet;
}
void AmfEventNotification::unsetReportList() {
  m_ReportListIsSet = false;
}

}  // namespace oai::nef::model
