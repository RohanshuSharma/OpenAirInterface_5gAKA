/**
 * Namf_Communication
 * AMF Communication Service © 2022, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.8
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "N1N2MessageTransferReqData.h"
#include "Helpers.h"

#include <sstream>

namespace oai::amf::model {

N1N2MessageTransferReqData::N1N2MessageTransferReqData() {
  m_N1MessageContainerIsSet     = false;
  m_N2InfoContainerIsSet        = false;
  m_MtDataIsSet                 = false;
  m_SkipInd                     = false;
  m_SkipIndIsSet                = false;
  m_LastMsgIndication           = false;
  m_LastMsgIndicationIsSet      = false;
  m_PduSessionId                = 0;
  m_PduSessionIdIsSet           = false;
  m_LcsCorrelationId            = "";
  m_LcsCorrelationIdIsSet       = false;
  m_Ppi                         = 0;
  m_PpiIsSet                    = false;
  m_ArpIsSet                    = false;
  m_r_5qi                       = 0;
  m_r_5qiIsSet                  = false;
  m_N1n2FailureTxfNotifURI      = "";
  m_N1n2FailureTxfNotifURIIsSet = false;
  m_SmfReallocationInd          = false;
  m_SmfReallocationIndIsSet     = false;
  m_AreaOfValidityIsSet         = false;
  m_SupportedFeatures           = "";
  m_SupportedFeaturesIsSet      = false;
  m_OldGuamiIsSet               = false;
  m_MaAcceptedInd               = false;
  m_MaAcceptedIndIsSet          = false;
  m_ExtBufSupport               = false;
  m_ExtBufSupportIsSet          = false;
  m_TargetAccessIsSet           = false;
}

void N1N2MessageTransferReqData::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::amf::helpers::ValidationException(msg.str());
  }
}

bool N1N2MessageTransferReqData::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool N1N2MessageTransferReqData::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "N1N2MessageTransferReqData" : pathPrefix;

  if (pduSessionIdIsSet()) {
    const int32_t& value               = m_PduSessionId;
    const std::string currentValuePath = _pathPrefix + ".pduSessionId";

    if (value < 0) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
    if (value > 255) {
      success = false;
      msg << currentValuePath << ": must be less than or equal to 255;";
    }
  }

  if (lcsCorrelationIdIsSet()) {
    const std::string& value           = m_LcsCorrelationId;
    const std::string currentValuePath = _pathPrefix + ".lcsCorrelationId";

    if (value.length() < 1) {
      success = false;
      msg << currentValuePath << ": must be at least 1 characters long;";
    }
    if (value.length() > 255) {
      success = false;
      msg << currentValuePath << ": must be at most 255 characters long;";
    }
  }

  if (ppiIsSet()) {
    const int32_t& value               = m_Ppi;
    const std::string currentValuePath = _pathPrefix + ".ppi";

    if (value < 0) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
    if (value > 7) {
      success = false;
      msg << currentValuePath << ": must be less than or equal to 7;";
    }
  }

  if (r5qiIsSet()) {
    const int32_t& value               = m_r_5qi;
    const std::string currentValuePath = _pathPrefix + ".r5qi";

    if (value < 0) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
    if (value > 255) {
      success = false;
      msg << currentValuePath << ": must be less than or equal to 255;";
    }
  }

  if (supportedFeaturesIsSet()) {
    const std::string& value           = m_SupportedFeatures;
    const std::string currentValuePath = _pathPrefix + ".supportedFeatures";
  }

  return success;
}

bool N1N2MessageTransferReqData::operator==(
    const N1N2MessageTransferReqData& rhs) const {
  return

      ((!n1MessageContainerIsSet() && !rhs.n1MessageContainerIsSet()) ||
       (n1MessageContainerIsSet() && rhs.n1MessageContainerIsSet() &&
        getN1MessageContainer() == rhs.getN1MessageContainer())) &&

      ((!n2InfoContainerIsSet() && !rhs.n2InfoContainerIsSet()) ||
       (n2InfoContainerIsSet() && rhs.n2InfoContainerIsSet() &&
        getN2InfoContainer() == rhs.getN2InfoContainer())) &&

      ((!mtDataIsSet() && !rhs.mtDataIsSet()) ||
       (mtDataIsSet() && rhs.mtDataIsSet() &&
        getMtData() == rhs.getMtData())) &&

      ((!skipIndIsSet() && !rhs.skipIndIsSet()) ||
       (skipIndIsSet() && rhs.skipIndIsSet() &&
        isSkipInd() == rhs.isSkipInd())) &&

      ((!lastMsgIndicationIsSet() && !rhs.lastMsgIndicationIsSet()) ||
       (lastMsgIndicationIsSet() && rhs.lastMsgIndicationIsSet() &&
        isLastMsgIndication() == rhs.isLastMsgIndication())) &&

      ((!pduSessionIdIsSet() && !rhs.pduSessionIdIsSet()) ||
       (pduSessionIdIsSet() && rhs.pduSessionIdIsSet() &&
        getPduSessionId() == rhs.getPduSessionId())) &&

      ((!lcsCorrelationIdIsSet() && !rhs.lcsCorrelationIdIsSet()) ||
       (lcsCorrelationIdIsSet() && rhs.lcsCorrelationIdIsSet() &&
        getLcsCorrelationId() == rhs.getLcsCorrelationId())) &&

      ((!ppiIsSet() && !rhs.ppiIsSet()) ||
       (ppiIsSet() && rhs.ppiIsSet() && getPpi() == rhs.getPpi())) &&

      ((!arpIsSet() && !rhs.arpIsSet()) ||
       (arpIsSet() && rhs.arpIsSet() && getArp() == rhs.getArp())) &&

      ((!r5qiIsSet() && !rhs.r5qiIsSet()) ||
       (r5qiIsSet() && rhs.r5qiIsSet() && getR5qi() == rhs.getR5qi())) &&

      ((!n1n2FailureTxfNotifURIIsSet() && !rhs.n1n2FailureTxfNotifURIIsSet()) ||
       (n1n2FailureTxfNotifURIIsSet() && rhs.n1n2FailureTxfNotifURIIsSet() &&
        getN1n2FailureTxfNotifURI() == rhs.getN1n2FailureTxfNotifURI())) &&

      ((!smfReallocationIndIsSet() && !rhs.smfReallocationIndIsSet()) ||
       (smfReallocationIndIsSet() && rhs.smfReallocationIndIsSet() &&
        isSmfReallocationInd() == rhs.isSmfReallocationInd())) &&

      ((!areaOfValidityIsSet() && !rhs.areaOfValidityIsSet()) ||
       (areaOfValidityIsSet() && rhs.areaOfValidityIsSet() &&
        getAreaOfValidity() == rhs.getAreaOfValidity())) &&

      ((!supportedFeaturesIsSet() && !rhs.supportedFeaturesIsSet()) ||
       (supportedFeaturesIsSet() && rhs.supportedFeaturesIsSet() &&
        getSupportedFeatures() == rhs.getSupportedFeatures())) &&

      ((!oldGuamiIsSet() && !rhs.oldGuamiIsSet()) ||
       (oldGuamiIsSet() && rhs.oldGuamiIsSet() &&
        getOldGuami() == rhs.getOldGuami())) &&

      ((!maAcceptedIndIsSet() && !rhs.maAcceptedIndIsSet()) ||
       (maAcceptedIndIsSet() && rhs.maAcceptedIndIsSet() &&
        isMaAcceptedInd() == rhs.isMaAcceptedInd())) &&

      ((!extBufSupportIsSet() && !rhs.extBufSupportIsSet()) ||
       (extBufSupportIsSet() && rhs.extBufSupportIsSet() &&
        isExtBufSupport() == rhs.isExtBufSupport())) &&

      ((!targetAccessIsSet() && !rhs.targetAccessIsSet()) ||
       (targetAccessIsSet() && rhs.targetAccessIsSet() &&
        getTargetAccess() == rhs.getTargetAccess()))

          ;
}

bool N1N2MessageTransferReqData::operator!=(
    const N1N2MessageTransferReqData& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const N1N2MessageTransferReqData& o) {
  j = nlohmann::json();
  if (o.n1MessageContainerIsSet())
    j["n1MessageContainer"] = o.m_N1MessageContainer;
  if (o.n2InfoContainerIsSet()) j["n2InfoContainer"] = o.m_N2InfoContainer;
  if (o.mtDataIsSet()) j["mtData"] = o.m_MtData;
  if (o.skipIndIsSet()) j["skipInd"] = o.m_SkipInd;
  if (o.lastMsgIndicationIsSet())
    j["lastMsgIndication"] = o.m_LastMsgIndication;
  if (o.pduSessionIdIsSet()) j["pduSessionId"] = o.m_PduSessionId;
  if (o.lcsCorrelationIdIsSet()) j["lcsCorrelationId"] = o.m_LcsCorrelationId;
  if (o.ppiIsSet()) j["ppi"] = o.m_Ppi;
  if (o.arpIsSet()) j["arp"] = o.m_Arp;
  if (o.r5qiIsSet()) j["5qi"] = o.m_r_5qi;
  if (o.n1n2FailureTxfNotifURIIsSet())
    j["n1n2FailureTxfNotifURI"] = o.m_N1n2FailureTxfNotifURI;
  if (o.smfReallocationIndIsSet())
    j["smfReallocationInd"] = o.m_SmfReallocationInd;
  if (o.areaOfValidityIsSet()) j["areaOfValidity"] = o.m_AreaOfValidity;
  if (o.supportedFeaturesIsSet())
    j["supportedFeatures"] = o.m_SupportedFeatures;
  if (o.oldGuamiIsSet()) j["oldGuami"] = o.m_OldGuami;
  if (o.maAcceptedIndIsSet()) j["maAcceptedInd"] = o.m_MaAcceptedInd;
  if (o.extBufSupportIsSet()) j["extBufSupport"] = o.m_ExtBufSupport;
  if (o.targetAccessIsSet()) j["targetAccess"] = o.m_TargetAccess;
}

void from_json(const nlohmann::json& j, N1N2MessageTransferReqData& o) {
  if (j.find("n1MessageContainer") != j.end()) {
    j.at("n1MessageContainer").get_to(o.m_N1MessageContainer);
    o.m_N1MessageContainerIsSet = true;
  }
  if (j.find("n2InfoContainer") != j.end()) {
    j.at("n2InfoContainer").get_to(o.m_N2InfoContainer);
    o.m_N2InfoContainerIsSet = true;
  }
  if (j.find("mtData") != j.end()) {
    j.at("mtData").get_to(o.m_MtData);
    o.m_MtDataIsSet = true;
  }
  if (j.find("skipInd") != j.end()) {
    j.at("skipInd").get_to(o.m_SkipInd);
    o.m_SkipIndIsSet = true;
  }
  if (j.find("lastMsgIndication") != j.end()) {
    j.at("lastMsgIndication").get_to(o.m_LastMsgIndication);
    o.m_LastMsgIndicationIsSet = true;
  }
  if (j.find("pduSessionId") != j.end()) {
    j.at("pduSessionId").get_to(o.m_PduSessionId);
    o.m_PduSessionIdIsSet = true;
  }
  if (j.find("lcsCorrelationId") != j.end()) {
    j.at("lcsCorrelationId").get_to(o.m_LcsCorrelationId);
    o.m_LcsCorrelationIdIsSet = true;
  }
  if (j.find("ppi") != j.end()) {
    j.at("ppi").get_to(o.m_Ppi);
    o.m_PpiIsSet = true;
  }
  if (j.find("arp") != j.end()) {
    j.at("arp").get_to(o.m_Arp);
    o.m_ArpIsSet = true;
  }
  if (j.find("5qi") != j.end()) {
    j.at("5qi").get_to(o.m_r_5qi);
    o.m_r_5qiIsSet = true;
  }
  if (j.find("n1n2FailureTxfNotifURI") != j.end()) {
    j.at("n1n2FailureTxfNotifURI").get_to(o.m_N1n2FailureTxfNotifURI);
    o.m_N1n2FailureTxfNotifURIIsSet = true;
  }
  if (j.find("smfReallocationInd") != j.end()) {
    j.at("smfReallocationInd").get_to(o.m_SmfReallocationInd);
    o.m_SmfReallocationIndIsSet = true;
  }
  if (j.find("areaOfValidity") != j.end()) {
    j.at("areaOfValidity").get_to(o.m_AreaOfValidity);
    o.m_AreaOfValidityIsSet = true;
  }
  if (j.find("supportedFeatures") != j.end()) {
    j.at("supportedFeatures").get_to(o.m_SupportedFeatures);
    o.m_SupportedFeaturesIsSet = true;
  }
  if (j.find("oldGuami") != j.end()) {
    j.at("oldGuami").get_to(o.m_OldGuami);
    o.m_OldGuamiIsSet = true;
  }
  if (j.find("maAcceptedInd") != j.end()) {
    j.at("maAcceptedInd").get_to(o.m_MaAcceptedInd);
    o.m_MaAcceptedIndIsSet = true;
  }
  if (j.find("extBufSupport") != j.end()) {
    j.at("extBufSupport").get_to(o.m_ExtBufSupport);
    o.m_ExtBufSupportIsSet = true;
  }
  if (j.find("targetAccess") != j.end()) {
    j.at("targetAccess").get_to(o.m_TargetAccess);
    o.m_TargetAccessIsSet = true;
  }
}

oai::amf::model::N1MessageContainer
N1N2MessageTransferReqData::getN1MessageContainer() const {
  return m_N1MessageContainer;
}
void N1N2MessageTransferReqData::setN1MessageContainer(
    oai::amf::model::N1MessageContainer const& value) {
  m_N1MessageContainer      = value;
  m_N1MessageContainerIsSet = true;
}
bool N1N2MessageTransferReqData::n1MessageContainerIsSet() const {
  return m_N1MessageContainerIsSet;
}
void N1N2MessageTransferReqData::unsetN1MessageContainer() {
  m_N1MessageContainerIsSet = false;
}
oai::amf::model::N2InfoContainer
N1N2MessageTransferReqData::getN2InfoContainer() const {
  return m_N2InfoContainer;
}
void N1N2MessageTransferReqData::setN2InfoContainer(
    oai::amf::model::N2InfoContainer const& value) {
  m_N2InfoContainer      = value;
  m_N2InfoContainerIsSet = true;
}
bool N1N2MessageTransferReqData::n2InfoContainerIsSet() const {
  return m_N2InfoContainerIsSet;
}
void N1N2MessageTransferReqData::unsetN2InfoContainer() {
  m_N2InfoContainerIsSet = false;
}
oai::amf::model::RefToBinaryData N1N2MessageTransferReqData::getMtData() const {
  return m_MtData;
}
void N1N2MessageTransferReqData::setMtData(
    oai::amf::model::RefToBinaryData const& value) {
  m_MtData      = value;
  m_MtDataIsSet = true;
}
bool N1N2MessageTransferReqData::mtDataIsSet() const {
  return m_MtDataIsSet;
}
void N1N2MessageTransferReqData::unsetMtData() {
  m_MtDataIsSet = false;
}
bool N1N2MessageTransferReqData::isSkipInd() const {
  return m_SkipInd;
}
void N1N2MessageTransferReqData::setSkipInd(bool const value) {
  m_SkipInd      = value;
  m_SkipIndIsSet = true;
}
bool N1N2MessageTransferReqData::skipIndIsSet() const {
  return m_SkipIndIsSet;
}
void N1N2MessageTransferReqData::unsetSkipInd() {
  m_SkipIndIsSet = false;
}
bool N1N2MessageTransferReqData::isLastMsgIndication() const {
  return m_LastMsgIndication;
}
void N1N2MessageTransferReqData::setLastMsgIndication(bool const value) {
  m_LastMsgIndication      = value;
  m_LastMsgIndicationIsSet = true;
}
bool N1N2MessageTransferReqData::lastMsgIndicationIsSet() const {
  return m_LastMsgIndicationIsSet;
}
void N1N2MessageTransferReqData::unsetLastMsgIndication() {
  m_LastMsgIndicationIsSet = false;
}
int32_t N1N2MessageTransferReqData::getPduSessionId() const {
  return m_PduSessionId;
}
void N1N2MessageTransferReqData::setPduSessionId(int32_t const value) {
  m_PduSessionId      = value;
  m_PduSessionIdIsSet = true;
}
bool N1N2MessageTransferReqData::pduSessionIdIsSet() const {
  return m_PduSessionIdIsSet;
}
void N1N2MessageTransferReqData::unsetPduSessionId() {
  m_PduSessionIdIsSet = false;
}
std::string N1N2MessageTransferReqData::getLcsCorrelationId() const {
  return m_LcsCorrelationId;
}
void N1N2MessageTransferReqData::setLcsCorrelationId(std::string const& value) {
  m_LcsCorrelationId      = value;
  m_LcsCorrelationIdIsSet = true;
}
bool N1N2MessageTransferReqData::lcsCorrelationIdIsSet() const {
  return m_LcsCorrelationIdIsSet;
}
void N1N2MessageTransferReqData::unsetLcsCorrelationId() {
  m_LcsCorrelationIdIsSet = false;
}
int32_t N1N2MessageTransferReqData::getPpi() const {
  return m_Ppi;
}
void N1N2MessageTransferReqData::setPpi(int32_t const value) {
  m_Ppi      = value;
  m_PpiIsSet = true;
}
bool N1N2MessageTransferReqData::ppiIsSet() const {
  return m_PpiIsSet;
}
void N1N2MessageTransferReqData::unsetPpi() {
  m_PpiIsSet = false;
}
oai::amf::model::Arp N1N2MessageTransferReqData::getArp() const {
  return m_Arp;
}
void N1N2MessageTransferReqData::setArp(oai::amf::model::Arp const& value) {
  m_Arp      = value;
  m_ArpIsSet = true;
}
bool N1N2MessageTransferReqData::arpIsSet() const {
  return m_ArpIsSet;
}
void N1N2MessageTransferReqData::unsetArp() {
  m_ArpIsSet = false;
}
int32_t N1N2MessageTransferReqData::getR5qi() const {
  return m_r_5qi;
}
void N1N2MessageTransferReqData::setR5qi(int32_t const value) {
  m_r_5qi      = value;
  m_r_5qiIsSet = true;
}
bool N1N2MessageTransferReqData::r5qiIsSet() const {
  return m_r_5qiIsSet;
}
void N1N2MessageTransferReqData::unsetr_5qi() {
  m_r_5qiIsSet = false;
}
std::string N1N2MessageTransferReqData::getN1n2FailureTxfNotifURI() const {
  return m_N1n2FailureTxfNotifURI;
}
void N1N2MessageTransferReqData::setN1n2FailureTxfNotifURI(
    std::string const& value) {
  m_N1n2FailureTxfNotifURI      = value;
  m_N1n2FailureTxfNotifURIIsSet = true;
}
bool N1N2MessageTransferReqData::n1n2FailureTxfNotifURIIsSet() const {
  return m_N1n2FailureTxfNotifURIIsSet;
}
void N1N2MessageTransferReqData::unsetN1n2FailureTxfNotifURI() {
  m_N1n2FailureTxfNotifURIIsSet = false;
}
bool N1N2MessageTransferReqData::isSmfReallocationInd() const {
  return m_SmfReallocationInd;
}
void N1N2MessageTransferReqData::setSmfReallocationInd(bool const value) {
  m_SmfReallocationInd      = value;
  m_SmfReallocationIndIsSet = true;
}
bool N1N2MessageTransferReqData::smfReallocationIndIsSet() const {
  return m_SmfReallocationIndIsSet;
}
void N1N2MessageTransferReqData::unsetSmfReallocationInd() {
  m_SmfReallocationIndIsSet = false;
}
oai::amf::model::AreaOfValidity N1N2MessageTransferReqData::getAreaOfValidity()
    const {
  return m_AreaOfValidity;
}
void N1N2MessageTransferReqData::setAreaOfValidity(
    oai::amf::model::AreaOfValidity const& value) {
  m_AreaOfValidity      = value;
  m_AreaOfValidityIsSet = true;
}
bool N1N2MessageTransferReqData::areaOfValidityIsSet() const {
  return m_AreaOfValidityIsSet;
}
void N1N2MessageTransferReqData::unsetAreaOfValidity() {
  m_AreaOfValidityIsSet = false;
}
std::string N1N2MessageTransferReqData::getSupportedFeatures() const {
  return m_SupportedFeatures;
}
void N1N2MessageTransferReqData::setSupportedFeatures(
    std::string const& value) {
  m_SupportedFeatures      = value;
  m_SupportedFeaturesIsSet = true;
}
bool N1N2MessageTransferReqData::supportedFeaturesIsSet() const {
  return m_SupportedFeaturesIsSet;
}
void N1N2MessageTransferReqData::unsetSupportedFeatures() {
  m_SupportedFeaturesIsSet = false;
}
oai::amf::model::Guami N1N2MessageTransferReqData::getOldGuami() const {
  return m_OldGuami;
}
void N1N2MessageTransferReqData::setOldGuami(
    oai::amf::model::Guami const& value) {
  m_OldGuami      = value;
  m_OldGuamiIsSet = true;
}
bool N1N2MessageTransferReqData::oldGuamiIsSet() const {
  return m_OldGuamiIsSet;
}
void N1N2MessageTransferReqData::unsetOldGuami() {
  m_OldGuamiIsSet = false;
}
bool N1N2MessageTransferReqData::isMaAcceptedInd() const {
  return m_MaAcceptedInd;
}
void N1N2MessageTransferReqData::setMaAcceptedInd(bool const value) {
  m_MaAcceptedInd      = value;
  m_MaAcceptedIndIsSet = true;
}
bool N1N2MessageTransferReqData::maAcceptedIndIsSet() const {
  return m_MaAcceptedIndIsSet;
}
void N1N2MessageTransferReqData::unsetMaAcceptedInd() {
  m_MaAcceptedIndIsSet = false;
}
bool N1N2MessageTransferReqData::isExtBufSupport() const {
  return m_ExtBufSupport;
}
void N1N2MessageTransferReqData::setExtBufSupport(bool const value) {
  m_ExtBufSupport      = value;
  m_ExtBufSupportIsSet = true;
}
bool N1N2MessageTransferReqData::extBufSupportIsSet() const {
  return m_ExtBufSupportIsSet;
}
void N1N2MessageTransferReqData::unsetExtBufSupport() {
  m_ExtBufSupportIsSet = false;
}
oai::amf::model::AccessType N1N2MessageTransferReqData::getTargetAccess()
    const {
  return m_TargetAccess;
}
void N1N2MessageTransferReqData::setTargetAccess(
    oai::amf::model::AccessType const& value) {
  m_TargetAccess      = value;
  m_TargetAccessIsSet = true;
}
bool N1N2MessageTransferReqData::targetAccessIsSet() const {
  return m_TargetAccessIsSet;
}
void N1N2MessageTransferReqData::unsetTargetAccess() {
  m_TargetAccessIsSet = false;
}

}  // namespace oai::amf::model
