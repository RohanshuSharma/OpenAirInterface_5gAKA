/**
 * Npcf_SMPolicyControl API
 * Session Management Policy Control Service © 2020, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.1.alpha-5
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "RedirectInformation.h"
#include "Helpers.h"

#include <sstream>

namespace oai {
namespace smf_server {
namespace model {

RedirectInformation::RedirectInformation() {
  m_RedirectEnabled            = false;
  m_RedirectEnabledIsSet       = false;
  m_RedirectAddressTypeIsSet   = false;
  m_RedirectServerAddress      = "";
  m_RedirectServerAddressIsSet = false;
}

void RedirectInformation::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    //        throw
    //        org::openapitools::server::helpers::ValidationException(msg.str());
  }
}

bool RedirectInformation::validate(std::stringstream& msg) const {
  return validate(msg, "");
}

bool RedirectInformation::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "RedirectInformation" : pathPrefix;

  return success;
}

bool RedirectInformation::operator==(const RedirectInformation& rhs) const {
  return

      ((!redirectEnabledIsSet() && !rhs.redirectEnabledIsSet()) ||
       (redirectEnabledIsSet() && rhs.redirectEnabledIsSet() &&
        isRedirectEnabled() == rhs.isRedirectEnabled())) &&

      ((!redirectAddressTypeIsSet() && !rhs.redirectAddressTypeIsSet()) ||
       (redirectAddressTypeIsSet() && rhs.redirectAddressTypeIsSet() &&
        getRedirectAddressType() == rhs.getRedirectAddressType())) &&

      ((!redirectServerAddressIsSet() && !rhs.redirectServerAddressIsSet()) ||
       (redirectServerAddressIsSet() && rhs.redirectServerAddressIsSet() &&
        getRedirectServerAddress() == rhs.getRedirectServerAddress()))

          ;
}

bool RedirectInformation::operator!=(const RedirectInformation& rhs) const {
  return !(*this == rhs);
}

void to_json(nlohmann::json& j, const RedirectInformation& o) {
  j = nlohmann::json();
  if (o.redirectEnabledIsSet()) j["redirectEnabled"] = o.m_RedirectEnabled;
  if (o.redirectAddressTypeIsSet())
    j["redirectAddressType"] = o.m_RedirectAddressType;
  if (o.redirectServerAddressIsSet())
    j["redirectServerAddress"] = o.m_RedirectServerAddress;
}

void from_json(const nlohmann::json& j, RedirectInformation& o) {
  if (j.find("redirectEnabled") != j.end()) {
    j.at("redirectEnabled").get_to(o.m_RedirectEnabled);
    o.m_RedirectEnabledIsSet = true;
  }
  if (j.find("redirectAddressType") != j.end()) {
    j.at("redirectAddressType").get_to(o.m_RedirectAddressType);
    o.m_RedirectAddressTypeIsSet = true;
  }
  if (j.find("redirectServerAddress") != j.end()) {
    j.at("redirectServerAddress").get_to(o.m_RedirectServerAddress);
    o.m_RedirectServerAddressIsSet = true;
  }
}

bool RedirectInformation::isRedirectEnabled() const {
  return m_RedirectEnabled;
}
void RedirectInformation::setRedirectEnabled(bool const value) {
  m_RedirectEnabled      = value;
  m_RedirectEnabledIsSet = true;
}
bool RedirectInformation::redirectEnabledIsSet() const {
  return m_RedirectEnabledIsSet;
}
void RedirectInformation::unsetRedirectEnabled() {
  m_RedirectEnabledIsSet = false;
}
RedirectAddressType RedirectInformation::getRedirectAddressType() const {
  return m_RedirectAddressType;
}
void RedirectInformation::setRedirectAddressType(
    RedirectAddressType const& value) {
  m_RedirectAddressType      = value;
  m_RedirectAddressTypeIsSet = true;
}
bool RedirectInformation::redirectAddressTypeIsSet() const {
  return m_RedirectAddressTypeIsSet;
}
void RedirectInformation::unsetRedirectAddressType() {
  m_RedirectAddressTypeIsSet = false;
}
std::string RedirectInformation::getRedirectServerAddress() const {
  return m_RedirectServerAddress;
}
void RedirectInformation::setRedirectServerAddress(std::string const& value) {
  m_RedirectServerAddress      = value;
  m_RedirectServerAddressIsSet = true;
}
bool RedirectInformation::redirectServerAddressIsSet() const {
  return m_RedirectServerAddressIsSet;
}
void RedirectInformation::unsetRedirectServerAddress() {
  m_RedirectServerAddressIsSet = false;
}

}  // namespace model
}  // namespace smf_server
}  // namespace oai
