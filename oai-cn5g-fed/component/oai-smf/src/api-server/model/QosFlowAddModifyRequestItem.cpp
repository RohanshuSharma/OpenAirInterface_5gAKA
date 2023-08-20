/**
 * Nsmf_PDUSession
 * SMF PDU Session Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "QosFlowAddModifyRequestItem.h"

namespace oai {
namespace smf_server {
namespace model {

QosFlowAddModifyRequestItem::QosFlowAddModifyRequestItem() {
  m_Qfi                     = 0;
  m_Ebi                     = 0;
  m_EbiIsSet                = false;
  m_QosRulesIsSet           = false;
  m_QosFlowDescriptionIsSet = false;
  m_QosFlowProfileIsSet     = false;
}

QosFlowAddModifyRequestItem::~QosFlowAddModifyRequestItem() {}

void QosFlowAddModifyRequestItem::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const QosFlowAddModifyRequestItem& o) {
  j        = nlohmann::json();
  j["qfi"] = o.m_Qfi;
  if (o.ebiIsSet()) j["ebi"] = o.m_Ebi;
  if (o.qosRulesIsSet()) j["qosRules"] = o.m_QosRules;
  if (o.qosFlowDescriptionIsSet())
    j["qosFlowDescription"] = o.m_QosFlowDescription;
  if (o.qosFlowProfileIsSet()) j["qosFlowProfile"] = o.m_QosFlowProfile;
}

void from_json(const nlohmann::json& j, QosFlowAddModifyRequestItem& o) {
  j.at("qfi").get_to(o.m_Qfi);
  if (j.find("ebi") != j.end()) {
    j.at("ebi").get_to(o.m_Ebi);
    o.m_EbiIsSet = true;
  }
  if (j.find("qosRules") != j.end()) {
    j.at("qosRules").get_to(o.m_QosRules);
    o.m_QosRulesIsSet = true;
  }
  if (j.find("qosFlowDescription") != j.end()) {
    j.at("qosFlowDescription").get_to(o.m_QosFlowDescription);
    o.m_QosFlowDescriptionIsSet = true;
  }
  if (j.find("qosFlowProfile") != j.end()) {
    j.at("qosFlowProfile").get_to(o.m_QosFlowProfile);
    o.m_QosFlowProfileIsSet = true;
  }
}

int32_t QosFlowAddModifyRequestItem::getQfi() const {
  return m_Qfi;
}
void QosFlowAddModifyRequestItem::setQfi(int32_t const value) {
  m_Qfi = value;
}
int32_t QosFlowAddModifyRequestItem::getEbi() const {
  return m_Ebi;
}
void QosFlowAddModifyRequestItem::setEbi(int32_t const value) {
  m_Ebi      = value;
  m_EbiIsSet = true;
}
bool QosFlowAddModifyRequestItem::ebiIsSet() const {
  return m_EbiIsSet;
}
void QosFlowAddModifyRequestItem::unsetEbi() {
  m_EbiIsSet = false;
}
std::string QosFlowAddModifyRequestItem::getQosRules() const {
  return m_QosRules;
}
void QosFlowAddModifyRequestItem::setQosRules(std::string const& value) {
  m_QosRules      = value;
  m_QosRulesIsSet = true;
}
bool QosFlowAddModifyRequestItem::qosRulesIsSet() const {
  return m_QosRulesIsSet;
}
void QosFlowAddModifyRequestItem::unsetQosRules() {
  m_QosRulesIsSet = false;
}
std::string QosFlowAddModifyRequestItem::getQosFlowDescription() const {
  return m_QosFlowDescription;
}
void QosFlowAddModifyRequestItem::setQosFlowDescription(
    std::string const& value) {
  m_QosFlowDescription      = value;
  m_QosFlowDescriptionIsSet = true;
}
bool QosFlowAddModifyRequestItem::qosFlowDescriptionIsSet() const {
  return m_QosFlowDescriptionIsSet;
}
void QosFlowAddModifyRequestItem::unsetQosFlowDescription() {
  m_QosFlowDescriptionIsSet = false;
}
QosFlowProfile QosFlowAddModifyRequestItem::getQosFlowProfile() const {
  return m_QosFlowProfile;
}
void QosFlowAddModifyRequestItem::setQosFlowProfile(
    QosFlowProfile const& value) {
  m_QosFlowProfile      = value;
  m_QosFlowProfileIsSet = true;
}
bool QosFlowAddModifyRequestItem::qosFlowProfileIsSet() const {
  return m_QosFlowProfileIsSet;
}
void QosFlowAddModifyRequestItem::unsetQosFlowProfile() {
  m_QosFlowProfileIsSet = false;
}

}  // namespace model
}  // namespace smf_server
}  // namespace oai