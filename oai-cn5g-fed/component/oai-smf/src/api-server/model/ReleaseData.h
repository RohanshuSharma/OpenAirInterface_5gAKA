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
/*
 * ReleaseData.h
 *
 *
 */

#ifndef ReleaseData_H_
#define ReleaseData_H_

#include "NgApCause.h"
#include "SecondaryRatUsageInfo.h"
#include "Cause.h"
#include <string>
#include "UserLocation.h"
#include "SecondaryRatUsageReport.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class ReleaseData {
 public:
  ReleaseData();
  virtual ~ReleaseData();

  void validate();

  /////////////////////////////////////////////
  /// ReleaseData members

  /// <summary>
  ///
  /// </summary>
  Cause getCause() const;
  void setCause(Cause const& value);
  bool causeIsSet() const;
  void unsetCause();
  /// <summary>
  ///
  /// </summary>
  NgApCause getNgApCause() const;
  void setNgApCause(NgApCause const& value);
  bool ngApCauseIsSet() const;
  void unsetNgApCause();
  /// <summary>
  ///
  /// </summary>
  int32_t get5gMmCauseValue() const;
  void set5gMmCauseValue(int32_t const value);
  bool _5gMmCauseValueIsSet() const;
  void unset_5gMmCauseValue();
  /// <summary>
  ///
  /// </summary>
  UserLocation getUeLocation() const;
  void setUeLocation(UserLocation const& value);
  bool ueLocationIsSet() const;
  void unsetUeLocation();
  /// <summary>
  ///
  /// </summary>
  std::string getUeTimeZone() const;
  void setUeTimeZone(std::string const& value);
  bool ueTimeZoneIsSet() const;
  void unsetUeTimeZone();
  /// <summary>
  ///
  /// </summary>
  UserLocation getAddUeLocation() const;
  void setAddUeLocation(UserLocation const& value);
  bool addUeLocationIsSet() const;
  void unsetAddUeLocation();
  /// <summary>
  ///
  /// </summary>
  std::vector<SecondaryRatUsageReport>& getSecondaryRatUsageReport();
  bool secondaryRatUsageReportIsSet() const;
  void unsetSecondaryRatUsageReport();
  /// <summary>
  ///
  /// </summary>
  std::vector<SecondaryRatUsageInfo>& getSecondaryRatUsageInfo();
  bool secondaryRatUsageInfoIsSet() const;
  void unsetSecondaryRatUsageInfo();

  friend void to_json(nlohmann::json& j, const ReleaseData& o);
  friend void from_json(const nlohmann::json& j, ReleaseData& o);

 protected:
  Cause m_Cause;
  bool m_CauseIsSet;
  NgApCause m_NgApCause;
  bool m_NgApCauseIsSet;
  int32_t m__5gMmCauseValue;
  bool m__5gMmCauseValueIsSet;
  UserLocation m_UeLocation;
  bool m_UeLocationIsSet;
  std::string m_UeTimeZone;
  bool m_UeTimeZoneIsSet;
  UserLocation m_AddUeLocation;
  bool m_AddUeLocationIsSet;
  std::vector<SecondaryRatUsageReport> m_SecondaryRatUsageReport;
  bool m_SecondaryRatUsageReportIsSet;
  std::vector<SecondaryRatUsageInfo> m_SecondaryRatUsageInfo;
  bool m_SecondaryRatUsageInfoIsSet;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai

#endif /* ReleaseData_H_ */
