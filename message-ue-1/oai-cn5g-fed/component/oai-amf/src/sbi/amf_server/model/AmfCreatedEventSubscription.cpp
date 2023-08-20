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

#include "AmfCreatedEventSubscription.h"
#include "Helpers.h"

#include <sstream>

namespace oai::amf::model {

AmfCreatedEventSubscription::AmfCreatedEventSubscription() {
  m_SubscriptionId         = "";
  m_ReportListIsSet        = false;
  m_SupportedFeatures      = "";
  m_SupportedFeaturesIsSet = false;
}

void AmfCreatedEventSubscription::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::amf::helpers::ValidationException(msg.str());
  }
}

bool AmfCreatedEventSubscription::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool AmfCreatedEventSubscription::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "AmfCreatedEventSubscription" : pathPrefix;

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

  if (supportedFeaturesIsSet()) {
    const std::string& value           = m_SupportedFeatures;
    const std::string currentValuePath = _pathPrefix + ".supportedFeatures";
  }

  return success;
}

bool AmfCreatedEventSubscription::operator==(
    const AmfCreatedEventSubscription& rhs) const {
  return

      (getSubscription() == rhs.getSubscription()) &&

      (getSubscriptionId() == rhs.getSubscriptionId()) &&

      ((!reportListIsSet() && !rhs.reportListIsSet()) ||
       (reportListIsSet() && rhs.reportListIsSet() &&
        getReportList() == rhs.getReportList())) &&

      ((!supportedFeaturesIsSet() && !rhs.supportedFeaturesIsSet()) ||
       (supportedFeaturesIsSet() && rhs.supportedFeaturesIsSet() &&
        getSupportedFeatures() == rhs.getSupportedFeatures()))

          ;
}

bool AmfCreatedEventSubscription::operator!=(
    const AmfCreatedEventSubscription& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const AmfCreatedEventSubscription& o) {
  j                   = nlohmann::json();
  j["subscription"]   = o.m_Subscription;
  j["subscriptionId"] = o.m_SubscriptionId;
  if (o.reportListIsSet() || !o.m_ReportList.empty())
    j["reportList"] = o.m_ReportList;
  if (o.supportedFeaturesIsSet())
    j["supportedFeatures"] = o.m_SupportedFeatures;
}

void from_json(const nlohmann::json& j, AmfCreatedEventSubscription& o) {
  j.at("subscription").get_to(o.m_Subscription);
  j.at("subscriptionId").get_to(o.m_SubscriptionId);
  if (j.find("reportList") != j.end()) {
    j.at("reportList").get_to(o.m_ReportList);
    o.m_ReportListIsSet = true;
  }
  if (j.find("supportedFeatures") != j.end()) {
    j.at("supportedFeatures").get_to(o.m_SupportedFeatures);
    o.m_SupportedFeaturesIsSet = true;
  }
}

AmfEventSubscription AmfCreatedEventSubscription::getSubscription() const {
  return m_Subscription;
}
void AmfCreatedEventSubscription::setSubscription(
    AmfEventSubscription const& value) {
  m_Subscription = value;
}
std::string AmfCreatedEventSubscription::getSubscriptionId() const {
  return m_SubscriptionId;
}
void AmfCreatedEventSubscription::setSubscriptionId(std::string const& value) {
  m_SubscriptionId = value;
}
std::vector<AmfEventReport> AmfCreatedEventSubscription::getReportList() const {
  return m_ReportList;
}
void AmfCreatedEventSubscription::setReportList(
    std::vector<AmfEventReport> const& value) {
  m_ReportList      = value;
  m_ReportListIsSet = true;
}
bool AmfCreatedEventSubscription::reportListIsSet() const {
  return m_ReportListIsSet;
}
void AmfCreatedEventSubscription::unsetReportList() {
  m_ReportListIsSet = false;
}
std::string AmfCreatedEventSubscription::getSupportedFeatures() const {
  return m_SupportedFeatures;
}
void AmfCreatedEventSubscription::setSupportedFeatures(
    std::string const& value) {
  m_SupportedFeatures      = value;
  m_SupportedFeaturesIsSet = true;
}
bool AmfCreatedEventSubscription::supportedFeaturesIsSet() const {
  return m_SupportedFeaturesIsSet;
}
void AmfCreatedEventSubscription::unsetSupportedFeatures() {
  m_SupportedFeaturesIsSet = false;
}

}  // namespace oai::amf::model
