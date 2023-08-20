/**
 * NRF NFManagement Service
 * NRF NFManagement Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * Helpers.h
 *
 * This is the helper class for models and primitives
 */

#ifndef Helpers_H_
#define Helpers_H_

#include "AccessType.h"
#include "AtsssCapability.h"
#include "ComplexQuery.h"
#include "DataSetId.h"
#include "EventId.h"
#include "Guami.h"
#include "Ipv6Prefix.h"
#include "NFType.h"
#include "NwdafEvent.h"
#include "PduSessionType.h"
#include "PlmnId.h"
#include "PlmnSnssai.h"
#include "ServiceName.h"
#include "SliceInfoForPDUSession.h"
#include "SliceInfoForRegistration.h"
#include "SliceInfoForUEConfigurationUpdate.h"
#include "Snssai.h"
#include "Tai.h"
#include <ctime>
#include <map>
#include <sstream>
#include <string>
#include <vector>

// #include "ServiceName.h"
// #include "PlmnSnssai.h"
// #include "PduSessionType.h"
// #include "EventId.h"
// #include "NwdafEvent.h"
// #include "ComplexQuery.h"
// #include "AtsssCapability.h"
// #include "Guami.h"
// #include "DataSetId.h"
// #include "Ipv6Prefix.h"
// #include "Atom.h"
// #include "CnfUnit.h"
// #include "Dnf.h"
// #include "Cnf.h"
// #include "DnfUnit.h"

namespace oai {
namespace nssf_server {
namespace helpers {

std::string toStringValue(const std::string& value);
std::string toStringValue(const int32_t& value);
std::string toStringValue(const int64_t& value);
std::string toStringValue(const bool& value);
std::string toStringValue(const float& value);
std::string toStringValue(const double& value);

bool fromStringValue(const std::string& inStr, std::string& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::NFType& value);

bool fromStringValue(const std::string& inStr, int32_t& value);
bool fromStringValue(const std::string& inStr, int64_t& value);
bool fromStringValue(const std::string& inStr, bool& value);
bool fromStringValue(const std::string& inStr, float& value);
bool fromStringValue(const std::string& inStr, double& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::ServiceName& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::PlmnId& value);
bool fromStringValue(
    const std::string& inStr,
    oai::nssf_server::model::SliceInfoForRegistration& value);
bool fromStringValue(
    const std::string& inStr,
    oai::nssf_server::model::SliceInfoForPDUSession& value);
bool fromStringValue(
    const std::string& inStr,
    oai::nssf_server::model::SliceInfoForUEConfigurationUpdate& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::Snssai& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::PlmnSnssai& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::PduSessionType& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::EventId& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::NwdafEvent& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::AccessType& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::ComplexQuery& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::AtsssCapability& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::Tai& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::Guami& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::Ipv6Prefix& value);
bool fromStringValue(
    const std::string& inStr, oai::nssf_server::model::DataSetId& value);

template<typename T>
bool fromStringValue(
    const std::vector<std::string>& inStr, std::vector<T>& value) {
  try {
    for (auto& item : inStr) {
      T itemValue;
      if (fromStringValue(item, itemValue)) {
        value.push_back(itemValue);
      }
    }
  } catch (...) {
    return false;
  }
  return value.size() > 0;
}
template<typename T>
bool fromStringValue(
    const std::string& inStr, std::vector<T>& value, char separator = ',') {
  std::vector<std::string> inStrings;
  std::istringstream f(inStr);
  std::string s;
  while (std::getline(f, s, separator)) {
    inStrings.push_back(s);
  }
  return fromStringValue(inStrings, value);
}

}  // namespace helpers
}  // namespace nssf_server
}  // namespace oai

#endif  // Helpers_H_
