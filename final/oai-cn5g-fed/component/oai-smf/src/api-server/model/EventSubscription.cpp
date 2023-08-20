/**
 * Nsmf_EventExposure
 * Session Management Event Exposure Service. © 2019, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "EventSubscription.h"

namespace oai {
namespace smf_server {
namespace model {

EventSubscription::EventSubscription() {
  m_DnaiChgTypeIsSet = false;
  m_DddTraDesIsSet   = false;
  m_DddStatiIsSet    = false;
}

EventSubscription::~EventSubscription() {}

void EventSubscription::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const EventSubscription& o) {
  j          = nlohmann::json();
  j["event"] = o.m_Event;
  if (o.dnaiChgTypeIsSet()) j["dnaiChgType"] = o.m_DnaiChgType;
  if (o.dddTraDesIsSet()) j["dddTraDes"] = o.m_DddTraDes;
  if (o.dddStatiIsSet() || !o.m_DddStati.empty()) j["dddStati"] = o.m_DddStati;
}

void from_json(const nlohmann::json& j, EventSubscription& o) {
  j.at("event").get_to(o.m_Event);
  if (j.find("dnaiChgType") != j.end()) {
    j.at("dnaiChgType").get_to(o.m_DnaiChgType);
    o.m_DnaiChgTypeIsSet = true;
  }
  if (j.find("dddTraDes") != j.end()) {
    j.at("dddTraDes").get_to(o.m_DddTraDes);
    o.m_DddTraDesIsSet = true;
  }
  if (j.find("dddStati") != j.end()) {
    j.at("dddStati").get_to(o.m_DddStati);
    o.m_DddStatiIsSet = true;
  }
}

SmfEvent EventSubscription::getEvent() const {
  return m_Event;
}
void EventSubscription::setEvent(SmfEvent const& value) {
  m_Event = value;
}
DnaiChangeType EventSubscription::getDnaiChgType() const {
  return m_DnaiChgType;
}
void EventSubscription::setDnaiChgType(DnaiChangeType const& value) {
  m_DnaiChgType      = value;
  m_DnaiChgTypeIsSet = true;
}
bool EventSubscription::dnaiChgTypeIsSet() const {
  return m_DnaiChgTypeIsSet;
}
void EventSubscription::unsetDnaiChgType() {
  m_DnaiChgTypeIsSet = false;
}
DddTrafficDescriptor EventSubscription::getDddTraDes() const {
  return m_DddTraDes;
}
void EventSubscription::setDddTraDes(DddTrafficDescriptor const& value) {
  m_DddTraDes      = value;
  m_DddTraDesIsSet = true;
}
bool EventSubscription::dddTraDesIsSet() const {
  return m_DddTraDesIsSet;
}
void EventSubscription::unsetDddTraDes() {
  m_DddTraDesIsSet = false;
}
std::vector<DddStatus>& EventSubscription::getDddStati() {
  return m_DddStati;
}
void EventSubscription::setDddStati(std::vector<DddStatus> const& value) {
  m_DddStati      = value;
  m_DddStatiIsSet = true;
}
bool EventSubscription::dddStatiIsSet() const {
  return m_DddStatiIsSet;
}
void EventSubscription::unsetDddStati() {
  m_DddStatiIsSet = false;
}

}  // namespace model
}  // namespace smf_server
}  // namespace oai
