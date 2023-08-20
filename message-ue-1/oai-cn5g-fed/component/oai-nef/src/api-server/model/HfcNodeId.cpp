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

#include "HfcNodeId.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

HfcNodeId::HfcNodeId() {
  m_HfcNId = "";
}

void HfcNodeId::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool HfcNodeId::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool HfcNodeId::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success                  = true;
  const std::string _pathPrefix = pathPrefix.empty() ? "HfcNodeId" : pathPrefix;

  /* HfcNId */ {
    const std::string& value           = m_HfcNId;
    const std::string currentValuePath = _pathPrefix + ".hfcNId";

    if (value.length() > 6) {
      success = false;
      msg << currentValuePath << ": must be at most 6 characters long;";
    }
  }

  return success;
}

bool HfcNodeId::operator==(const HfcNodeId& rhs) const {
  return

      (getHfcNId() == rhs.getHfcNId())

          ;
}

bool HfcNodeId::operator!=(const HfcNodeId& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const HfcNodeId& o) {
  j           = nlohmann::json();
  j["hfcNId"] = o.m_HfcNId;
}

void from_json(const nlohmann::json& j, HfcNodeId& o) {
  j.at("hfcNId").get_to(o.m_HfcNId);
}

std::string HfcNodeId::getHfcNId() const {
  return m_HfcNId;
}
void HfcNodeId::setHfcNId(std::string const& value) {
  m_HfcNId = value;
}

}  // namespace oai::nef::model
