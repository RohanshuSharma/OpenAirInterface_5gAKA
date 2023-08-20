/**
 * 3gpp-analyticsexposure
 * API for Analytics Exposure. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.3
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "QosRequirement.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

QosRequirement::QosRequirement() {
  m_r_5qi        = 0;
  m_r_5qiIsSet   = false;
  m_GfbrUl       = "";
  m_GfbrUlIsSet  = false;
  m_GfbrDl       = "";
  m_GfbrDlIsSet  = false;
  m_ResTypeIsSet = false;
  m_Pdb          = 0;
  m_PdbIsSet     = false;
  m_Per          = "";
  m_PerIsSet     = false;
}

void QosRequirement::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool QosRequirement::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool QosRequirement::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "QosRequirement" : pathPrefix;

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

  if (gfbrUlIsSet()) {
    const std::string& value           = m_GfbrUl;
    const std::string currentValuePath = _pathPrefix + ".gfbrUl";
  }

  if (gfbrDlIsSet()) {
    const std::string& value           = m_GfbrDl;
    const std::string currentValuePath = _pathPrefix + ".gfbrDl";
  }

  if (pdbIsSet()) {
    const int32_t& value               = m_Pdb;
    const std::string currentValuePath = _pathPrefix + ".pdb";

    if (value < 1) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 1;";
    }
  }

  if (perIsSet()) {
    const std::string& value           = m_Per;
    const std::string currentValuePath = _pathPrefix + ".per";
  }

  return success;
}

bool QosRequirement::operator==(const QosRequirement& rhs) const {
  return

      ((!r5qiIsSet() && !rhs.r5qiIsSet()) ||
       (r5qiIsSet() && rhs.r5qiIsSet() && getR5qi() == rhs.getR5qi())) &&

      ((!gfbrUlIsSet() && !rhs.gfbrUlIsSet()) ||
       (gfbrUlIsSet() && rhs.gfbrUlIsSet() &&
        getGfbrUl() == rhs.getGfbrUl())) &&

      ((!gfbrDlIsSet() && !rhs.gfbrDlIsSet()) ||
       (gfbrDlIsSet() && rhs.gfbrDlIsSet() &&
        getGfbrDl() == rhs.getGfbrDl())) &&

      ((!resTypeIsSet() && !rhs.resTypeIsSet()) ||
       (resTypeIsSet() && rhs.resTypeIsSet() &&
        getResType() == rhs.getResType())) &&

      ((!pdbIsSet() && !rhs.pdbIsSet()) ||
       (pdbIsSet() && rhs.pdbIsSet() && getPdb() == rhs.getPdb())) &&

      ((!perIsSet() && !rhs.perIsSet()) ||
       (perIsSet() && rhs.perIsSet() && getPer() == rhs.getPer()))

          ;
}

bool QosRequirement::operator!=(const QosRequirement& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const QosRequirement& o) {
  j = nlohmann::json();
  if (o.r5qiIsSet()) j["5qi"] = o.m_r_5qi;
  if (o.gfbrUlIsSet()) j["gfbrUl"] = o.m_GfbrUl;
  if (o.gfbrDlIsSet()) j["gfbrDl"] = o.m_GfbrDl;
  if (o.resTypeIsSet()) j["resType"] = o.m_ResType;
  if (o.pdbIsSet()) j["pdb"] = o.m_Pdb;
  if (o.perIsSet()) j["per"] = o.m_Per;
}

void from_json(const nlohmann::json& j, QosRequirement& o) {
  if (j.find("5qi") != j.end()) {
    j.at("5qi").get_to(o.m_r_5qi);
    o.m_r_5qiIsSet = true;
  }
  if (j.find("gfbrUl") != j.end()) {
    j.at("gfbrUl").get_to(o.m_GfbrUl);
    o.m_GfbrUlIsSet = true;
  }
  if (j.find("gfbrDl") != j.end()) {
    j.at("gfbrDl").get_to(o.m_GfbrDl);
    o.m_GfbrDlIsSet = true;
  }
  if (j.find("resType") != j.end()) {
    j.at("resType").get_to(o.m_ResType);
    o.m_ResTypeIsSet = true;
  }
  if (j.find("pdb") != j.end()) {
    j.at("pdb").get_to(o.m_Pdb);
    o.m_PdbIsSet = true;
  }
  if (j.find("per") != j.end()) {
    j.at("per").get_to(o.m_Per);
    o.m_PerIsSet = true;
  }
}

int32_t QosRequirement::getR5qi() const {
  return m_r_5qi;
}
void QosRequirement::setR5qi(int32_t const value) {
  m_r_5qi      = value;
  m_r_5qiIsSet = true;
}
bool QosRequirement::r5qiIsSet() const {
  return m_r_5qiIsSet;
}
void QosRequirement::unsetr_5qi() {
  m_r_5qiIsSet = false;
}
std::string QosRequirement::getGfbrUl() const {
  return m_GfbrUl;
}
void QosRequirement::setGfbrUl(std::string const& value) {
  m_GfbrUl      = value;
  m_GfbrUlIsSet = true;
}
bool QosRequirement::gfbrUlIsSet() const {
  return m_GfbrUlIsSet;
}
void QosRequirement::unsetGfbrUl() {
  m_GfbrUlIsSet = false;
}
std::string QosRequirement::getGfbrDl() const {
  return m_GfbrDl;
}
void QosRequirement::setGfbrDl(std::string const& value) {
  m_GfbrDl      = value;
  m_GfbrDlIsSet = true;
}
bool QosRequirement::gfbrDlIsSet() const {
  return m_GfbrDlIsSet;
}
void QosRequirement::unsetGfbrDl() {
  m_GfbrDlIsSet = false;
}
QosResourceType QosRequirement::getResType() const {
  return m_ResType;
}
void QosRequirement::setResType(QosResourceType const& value) {
  m_ResType      = value;
  m_ResTypeIsSet = true;
}
bool QosRequirement::resTypeIsSet() const {
  return m_ResTypeIsSet;
}
void QosRequirement::unsetResType() {
  m_ResTypeIsSet = false;
}
int32_t QosRequirement::getPdb() const {
  return m_Pdb;
}
void QosRequirement::setPdb(int32_t const value) {
  m_Pdb      = value;
  m_PdbIsSet = true;
}
bool QosRequirement::pdbIsSet() const {
  return m_PdbIsSet;
}
void QosRequirement::unsetPdb() {
  m_PdbIsSet = false;
}
std::string QosRequirement::getPer() const {
  return m_Per;
}
void QosRequirement::setPer(std::string const& value) {
  m_Per      = value;
  m_PerIsSet = true;
}
bool QosRequirement::perIsSet() const {
  return m_PerIsSet;
}
void QosRequirement::unsetPer() {
  m_PerIsSet = false;
}

}  // namespace oai::nef::model