/**
 * NSSF NSSAI Availability
 * NSSF NSSAI Availability Service. © 2021, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.4
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "NssfEventSubscriptionCreateData.h"
#include "Helpers.h"

#include <sstream>

namespace oai {
namespace nssf_server {
namespace model {

NssfEventSubscriptionCreateData::NssfEventSubscriptionCreateData() {
  m_NfNssaiAvailabilityUri = "";
  m_Expiry                 = "";
  m_ExpiryIsSet            = false;
  m_AmfSetId               = "";
  m_AmfSetIdIsSet          = false;
  m_TaiRangeListIsSet      = false;
  m_SupportedFeatures      = "";
  m_SupportedFeaturesIsSet = false;
}

void NssfEventSubscriptionCreateData::validate() const {
  std::stringstream msg;
  // if (!validate(msg))
  // {
  //     throw oai::nssf_server::helpers::ValidationException(msg.str());
  // }
}

bool NssfEventSubscriptionCreateData::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool NssfEventSubscriptionCreateData::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "NssfEventSubscriptionCreateData" : pathPrefix;

  /* TaiList */ {
    const std::vector<Tai>& value      = m_TaiList;
    const std::string currentValuePath = _pathPrefix + ".taiList";

    {  // Recursive validation of array elements
      const std::string oldValuePath = currentValuePath;
      int i                          = 0;
      for (const Tai& value : value) {
        const std::string currentValuePath =
            oldValuePath + "[" + std::to_string(i) + "]";

        success = value.validate(msg, currentValuePath + ".taiList") && success;

        i++;
      }
    }
  }

  if (amfSetIdIsSet()) {
    const std::string& value           = m_AmfSetId;
    const std::string currentValuePath = _pathPrefix + ".amfSetId";
  }

  if (taiRangeListIsSet()) {
    const std::vector<TaiRange>& value = m_TaiRangeList;
    const std::string currentValuePath = _pathPrefix + ".taiRangeList";

    if (value.size() < 1) {
      success = false;
      msg << currentValuePath << ": must have at least 1 elements;";
    }
    {  // Recursive validation of array elements
      const std::string oldValuePath = currentValuePath;
      int i                          = 0;
      for (const TaiRange& value : value) {
        const std::string currentValuePath =
            oldValuePath + "[" + std::to_string(i) + "]";

        success =
            value.validate(msg, currentValuePath + ".taiRangeList") && success;

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

bool NssfEventSubscriptionCreateData::operator==(
    const NssfEventSubscriptionCreateData& rhs) const {
  return

      (getNfNssaiAvailabilityUri() == rhs.getNfNssaiAvailabilityUri()) &&

      (getTaiList() == rhs.getTaiList()) &&

      (getEvent() == rhs.getEvent()) &&

      ((!expiryIsSet() && !rhs.expiryIsSet()) ||
       (expiryIsSet() && rhs.expiryIsSet() &&
        getExpiry() == rhs.getExpiry())) &&

      ((!amfSetIdIsSet() && !rhs.amfSetIdIsSet()) ||
       (amfSetIdIsSet() && rhs.amfSetIdIsSet() &&
        getAmfSetId() == rhs.getAmfSetId())) &&

      ((!taiRangeListIsSet() && !rhs.taiRangeListIsSet()) ||
       (taiRangeListIsSet() && rhs.taiRangeListIsSet() &&
        getTaiRangeList() == rhs.getTaiRangeList())) &&

      ((!supportedFeaturesIsSet() && !rhs.supportedFeaturesIsSet()) ||
       (supportedFeaturesIsSet() && rhs.supportedFeaturesIsSet() &&
        getSupportedFeatures() == rhs.getSupportedFeatures()))

          ;
}

bool NssfEventSubscriptionCreateData::operator!=(
    const NssfEventSubscriptionCreateData& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const NssfEventSubscriptionCreateData& o) {
  j                           = nlohmann::json();
  j["nfNssaiAvailabilityUri"] = o.m_NfNssaiAvailabilityUri;
  j["taiList"]                = o.m_TaiList;
  j["event"]                  = o.m_Event;
  if (o.expiryIsSet()) j["expiry"] = o.m_Expiry;
  if (o.amfSetIdIsSet()) j["amfSetId"] = o.m_AmfSetId;
  if (o.taiRangeListIsSet() || !o.m_TaiRangeList.empty())
    j["taiRangeList"] = o.m_TaiRangeList;
  if (o.supportedFeaturesIsSet())
    j["supportedFeatures"] = o.m_SupportedFeatures;
}

void from_json(const nlohmann::json& j, NssfEventSubscriptionCreateData& o) {
  j.at("nfNssaiAvailabilityUri").get_to(o.m_NfNssaiAvailabilityUri);
  j.at("taiList").get_to(o.m_TaiList);
  j.at("event").get_to(o.m_Event);
  if (j.find("expiry") != j.end()) {
    j.at("expiry").get_to(o.m_Expiry);
    o.m_ExpiryIsSet = true;
  }
  if (j.find("amfSetId") != j.end()) {
    j.at("amfSetId").get_to(o.m_AmfSetId);
    o.m_AmfSetIdIsSet = true;
  }
  if (j.find("taiRangeList") != j.end()) {
    j.at("taiRangeList").get_to(o.m_TaiRangeList);
    o.m_TaiRangeListIsSet = true;
  }
  if (j.find("supportedFeatures") != j.end()) {
    j.at("supportedFeatures").get_to(o.m_SupportedFeatures);
    o.m_SupportedFeaturesIsSet = true;
  }
}

std::string NssfEventSubscriptionCreateData::getNfNssaiAvailabilityUri() const {
  return m_NfNssaiAvailabilityUri;
}
void NssfEventSubscriptionCreateData::setNfNssaiAvailabilityUri(
    std::string const& value) {
  m_NfNssaiAvailabilityUri = value;
}
std::vector<Tai> NssfEventSubscriptionCreateData::getTaiList() const {
  return m_TaiList;
}
void NssfEventSubscriptionCreateData::setTaiList(
    std::vector<Tai> const& value) {
  m_TaiList = value;
}
NssfEventType NssfEventSubscriptionCreateData::getEvent() const {
  return m_Event;
}
void NssfEventSubscriptionCreateData::setEvent(NssfEventType const& value) {
  m_Event = value;
}
std::string NssfEventSubscriptionCreateData::getExpiry() const {
  return m_Expiry;
}
void NssfEventSubscriptionCreateData::setExpiry(std::string const& value) {
  m_Expiry      = value;
  m_ExpiryIsSet = true;
}
bool NssfEventSubscriptionCreateData::expiryIsSet() const {
  return m_ExpiryIsSet;
}
void NssfEventSubscriptionCreateData::unsetExpiry() {
  m_ExpiryIsSet = false;
}
std::string NssfEventSubscriptionCreateData::getAmfSetId() const {
  return m_AmfSetId;
}
void NssfEventSubscriptionCreateData::setAmfSetId(std::string const& value) {
  m_AmfSetId      = value;
  m_AmfSetIdIsSet = true;
}
bool NssfEventSubscriptionCreateData::amfSetIdIsSet() const {
  return m_AmfSetIdIsSet;
}
void NssfEventSubscriptionCreateData::unsetAmfSetId() {
  m_AmfSetIdIsSet = false;
}
std::vector<TaiRange> NssfEventSubscriptionCreateData::getTaiRangeList() const {
  return m_TaiRangeList;
}
void NssfEventSubscriptionCreateData::setTaiRangeList(
    std::vector<TaiRange> const& value) {
  m_TaiRangeList      = value;
  m_TaiRangeListIsSet = true;
}
bool NssfEventSubscriptionCreateData::taiRangeListIsSet() const {
  return m_TaiRangeListIsSet;
}
void NssfEventSubscriptionCreateData::unsetTaiRangeList() {
  m_TaiRangeListIsSet = false;
}
std::string NssfEventSubscriptionCreateData::getSupportedFeatures() const {
  return m_SupportedFeatures;
}
void NssfEventSubscriptionCreateData::setSupportedFeatures(
    std::string const& value) {
  m_SupportedFeatures      = value;
  m_SupportedFeaturesIsSet = true;
}
bool NssfEventSubscriptionCreateData::supportedFeaturesIsSet() const {
  return m_SupportedFeaturesIsSet;
}
void NssfEventSubscriptionCreateData::unsetSupportedFeatures() {
  m_SupportedFeaturesIsSet = false;
}

}  // namespace model
}  // namespace nssf_server
}  // namespace oai
