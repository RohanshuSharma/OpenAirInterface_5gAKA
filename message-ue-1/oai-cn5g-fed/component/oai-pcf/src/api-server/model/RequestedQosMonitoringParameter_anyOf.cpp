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

#include "RequestedQosMonitoringParameter_anyOf.h"
#include "Helpers.h"
#include <stdexcept>
#include <sstream>

namespace oai {
namespace pcf {
namespace model {

RequestedQosMonitoringParameter_anyOf::RequestedQosMonitoringParameter_anyOf() {

}

void RequestedQosMonitoringParameter_anyOf::validate() const {
  std::stringstream msg;
  if (!validate(msg)) {
    //        throw
    //        org::openapitools::server::helpers::ValidationException(msg.str());
  }
}

bool RequestedQosMonitoringParameter_anyOf::validate(
    std::stringstream& msg) const {
  return validate(msg, "");
}

bool RequestedQosMonitoringParameter_anyOf::validate(
    std::stringstream& msg, const std::string& pathPrefix) const {
  bool success = true;
  const std::string _pathPrefix =
      pathPrefix.empty() ? "RequestedQosMonitoringParameter_anyOf" : pathPrefix;

  if (m_value == RequestedQosMonitoringParameter_anyOf::
                     eRequestedQosMonitoringParameter_anyOf::
                         INVALID_VALUE_OPENAPI_GENERATED) {
    success = false;
    msg << _pathPrefix << ": has no value;";
  }

  return success;
}

bool RequestedQosMonitoringParameter_anyOf::operator==(
    const RequestedQosMonitoringParameter_anyOf& rhs) const {
  return getValue() == rhs.getValue()

      ;
}

bool RequestedQosMonitoringParameter_anyOf::operator!=(
    const RequestedQosMonitoringParameter_anyOf& rhs) const {
  return !(*this == rhs);
}

void to_json(
    nlohmann::json& j, const RequestedQosMonitoringParameter_anyOf& o) {
  j = nlohmann::json();

  switch (o.getValue()) {
    case RequestedQosMonitoringParameter_anyOf::
        eRequestedQosMonitoringParameter_anyOf::INVALID_VALUE_OPENAPI_GENERATED:
      j = "INVALID_VALUE_OPENAPI_GENERATED";
      break;
    case RequestedQosMonitoringParameter_anyOf::
        eRequestedQosMonitoringParameter_anyOf::DOWNLINK:
      j = "DOWNLINK";
      break;
    case RequestedQosMonitoringParameter_anyOf::
        eRequestedQosMonitoringParameter_anyOf::UPLINK:
      j = "UPLINK";
      break;
    case RequestedQosMonitoringParameter_anyOf::
        eRequestedQosMonitoringParameter_anyOf::ROUND_TRIP:
      j = "ROUND_TRIP";
      break;
  }
}

void from_json(
    const nlohmann::json& j, RequestedQosMonitoringParameter_anyOf& o) {
  auto s = j.get<std::string>();
  if (s == "DOWNLINK") {
    o.setValue(RequestedQosMonitoringParameter_anyOf::
                   eRequestedQosMonitoringParameter_anyOf::DOWNLINK);
  } else if (s == "UPLINK") {
    o.setValue(RequestedQosMonitoringParameter_anyOf::
                   eRequestedQosMonitoringParameter_anyOf::UPLINK);
  } else if (s == "ROUND_TRIP") {
    o.setValue(RequestedQosMonitoringParameter_anyOf::
                   eRequestedQosMonitoringParameter_anyOf::ROUND_TRIP);
  } else {
    std::stringstream ss;
    ss << "Unexpected value " << s << " in json"
       << " cannot be converted to enum of type"
       << " RequestedQosMonitoringParameter_anyOf::"
          "eRequestedQosMonitoringParameter_anyOf";
    throw std::invalid_argument(ss.str());
  }
}

RequestedQosMonitoringParameter_anyOf::eRequestedQosMonitoringParameter_anyOf
RequestedQosMonitoringParameter_anyOf::getValue() const {
  return m_value;
}
void RequestedQosMonitoringParameter_anyOf::setValue(
    RequestedQosMonitoringParameter_anyOf::
        eRequestedQosMonitoringParameter_anyOf value) {
  m_value = value;
}

}  // namespace model
}  // namespace pcf
}  // namespace oai
