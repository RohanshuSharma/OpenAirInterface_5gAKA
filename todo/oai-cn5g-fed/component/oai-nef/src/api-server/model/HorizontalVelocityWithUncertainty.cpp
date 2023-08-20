/**
 * 3gpp-mo-lcs-notify
 * API for UE updated location information notification. © 2021, 3GPP
 * Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights
 * reserved.
 *
 * The version of the OpenAPI document: 1.0.1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "HorizontalVelocityWithUncertainty.h"

#include <sstream>

#include "Helpers.h"

namespace oai::nef::model {

HorizontalVelocityWithUncertainty::HorizontalVelocityWithUncertainty() {
  m_HSpeed       = 0.0f;
  m_Bearing      = 0;
  m_HUncertainty = 0.0f;
}

void HorizontalVelocityWithUncertainty::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    throw oai::nef::helpers::ValidationException(msg.str());
  }
}

bool HorizontalVelocityWithUncertainty::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool HorizontalVelocityWithUncertainty::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "HorizontalVelocityWithUncertainty" : pathPrefix;

  /* HSpeed */ {
    const float& value                 = m_HSpeed;
    const std::string currentValuePath = _pathPrefix + ".hSpeed";

    if (value < static_cast<float>(0)) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
    if (value > static_cast<float>(2047)) {
      success = false;
      msg << currentValuePath << ": must be less than or equal to 2047;";
    }
  }

  /* Bearing */ {
    const int32_t& value               = m_Bearing;
    const std::string currentValuePath = _pathPrefix + ".bearing";

    if (value < 0) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
    if (value > 360) {
      success = false;
      msg << currentValuePath << ": must be less than or equal to 360;";
    }
  }

  /* HUncertainty */ {
    const float& value                 = m_HUncertainty;
    const std::string currentValuePath = _pathPrefix + ".hUncertainty";

    if (value < static_cast<float>(0)) {
      success = false;
      msg << currentValuePath << ": must be greater than or equal to 0;";
    }
    if (value > static_cast<float>(255)) {
      success = false;
      msg << currentValuePath << ": must be less than or equal to 255;";
    }
  }

  return success;
}

bool HorizontalVelocityWithUncertainty::operator==(
    const HorizontalVelocityWithUncertainty& rhs) const {
  return

      (getHSpeed() == rhs.getHSpeed()) &&

      (getBearing() == rhs.getBearing()) &&

      (getHUncertainty() == rhs.getHUncertainty())

          ;
}

bool HorizontalVelocityWithUncertainty::operator!=(
    const HorizontalVelocityWithUncertainty& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const HorizontalVelocityWithUncertainty& o) {
  j                 = nlohmann::json();
  j["hSpeed"]       = o.m_HSpeed;
  j["bearing"]      = o.m_Bearing;
  j["hUncertainty"] = o.m_HUncertainty;
}

void from_json(const nlohmann::json& j, HorizontalVelocityWithUncertainty& o) {
  j.at("hSpeed").get_to(o.m_HSpeed);
  j.at("bearing").get_to(o.m_Bearing);
  j.at("hUncertainty").get_to(o.m_HUncertainty);
}

float HorizontalVelocityWithUncertainty::getHSpeed() const {
  return m_HSpeed;
}
void HorizontalVelocityWithUncertainty::setHSpeed(float const value) {
  m_HSpeed = value;
}
int32_t HorizontalVelocityWithUncertainty::getBearing() const {
  return m_Bearing;
}
void HorizontalVelocityWithUncertainty::setBearing(int32_t const value) {
  m_Bearing = value;
}
float HorizontalVelocityWithUncertainty::getHUncertainty() const {
  return m_HUncertainty;
}
void HorizontalVelocityWithUncertainty::setHUncertainty(float const value) {
  m_HUncertainty = value;
}

}  // namespace oai::nef::model