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
/*
 * GeraLocation.h
 *
 * Exactly one of cgi, sai or lai shall be present.
 */

#ifndef GeraLocation_H_
#define GeraLocation_H_

#include <nlohmann/json.hpp>
#include <string>

#include "CellGlobalId.h"
#include "LocationAreaId.h"
#include "RoutingAreaId.h"
#include "ServiceAreaId.h"

namespace oai::nef::model {

/// <summary>
/// Exactly one of cgi, sai or lai shall be present.
/// </summary>
class GeraLocation {
 public:
  GeraLocation();
  virtual ~GeraLocation() = default;

  /// <summary>
  /// Validate the current data in the model. Throws a ValidationException on
  /// failure.
  /// </summary>
  void validate() const;

  /// <summary>
  /// Validate the current data in the model. Returns false on error and writes
  /// an error message into the given stringstream.
  /// </summary>
  bool validate(std::stringstream& msg) const;

  /// <summary>
  /// Helper overload for validate. Used when one model stores another model and
  /// calls it's validate. Not meant to be called outside that case.
  /// </summary>
  bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

  bool operator==(const GeraLocation& rhs) const;
  bool operator!=(const GeraLocation& rhs) const;

  /////////////////////////////////////////////
  /// GeraLocation members

  /// <summary>
  /// Location number within the PLMN. See 3GPP TS 23.003, clause 4.5.
  /// </summary>
  std::string getLocationNumber() const;
  void setLocationNumber(std::string const& value);
  bool locationNumberIsSet() const;
  void unsetLocationNumber();
  /// <summary>
  ///
  /// </summary>
  CellGlobalId getCgi() const;
  void setCgi(CellGlobalId const& value);
  bool cgiIsSet() const;
  void unsetCgi();
  /// <summary>
  ///
  /// </summary>
  RoutingAreaId getRai() const;
  void setRai(RoutingAreaId const& value);
  bool raiIsSet() const;
  void unsetRai();
  /// <summary>
  ///
  /// </summary>
  ServiceAreaId getSai() const;
  void setSai(ServiceAreaId const& value);
  bool saiIsSet() const;
  void unsetSai();
  /// <summary>
  ///
  /// </summary>
  LocationAreaId getLai() const;
  void setLai(LocationAreaId const& value);
  bool laiIsSet() const;
  void unsetLai();
  /// <summary>
  /// VLR number. See 3GPP TS 23.003 clause 5.1.
  /// </summary>
  std::string getVlrNumber() const;
  void setVlrNumber(std::string const& value);
  bool vlrNumberIsSet() const;
  void unsetVlrNumber();
  /// <summary>
  /// MSC number. See 3GPP TS 23.003 clause 5.1.
  /// </summary>
  std::string getMscNumber() const;
  void setMscNumber(std::string const& value);
  bool mscNumberIsSet() const;
  void unsetMscNumber();
  /// <summary>
  /// The value represents the elapsed time in minutes since the last network
  /// contact of the mobile station.  Value \&quot;0\&quot; indicates that the
  /// location information was obtained after a successful paging procedure for
  /// Active Location Retrieval when the UE is in idle mode or after a
  /// successful location reporting procedure the UE is in connected mode.Any
  /// other value than \&quot;0\&quot; indicates that the location information
  /// is the last known one.See 3GPP TS 29.002 clause 17.7.8.
  /// </summary>
  int32_t getAgeOfLocationInformation() const;
  void setAgeOfLocationInformation(int32_t const value);
  bool ageOfLocationInformationIsSet() const;
  void unsetAgeOfLocationInformation();
  /// <summary>
  /// string with format \&quot;date-time\&quot; as defined in OpenAPI.
  /// </summary>
  std::string getUeLocationTimestamp() const;
  void setUeLocationTimestamp(std::string const& value);
  bool ueLocationTimestampIsSet() const;
  void unsetUeLocationTimestamp();
  /// <summary>
  /// Refer to geographical Information.See 3GPP TS 23.032 clause 7.3.2. Only
  /// the description of an ellipsoid point with uncertainty circle is allowed
  /// to be used.
  /// </summary>
  std::string getGeographicalInformation() const;
  void setGeographicalInformation(std::string const& value);
  bool geographicalInformationIsSet() const;
  void unsetGeographicalInformation();
  /// <summary>
  /// Refers to Calling Geodetic Location.See ITU-T Recommendation Q.763 (1999)
  /// clause 3.88.2. Only the description of an ellipsoid point with uncertainty
  /// circle is allowed to be used.
  /// </summary>
  std::string getGeodeticInformation() const;
  void setGeodeticInformation(std::string const& value);
  bool geodeticInformationIsSet() const;
  void unsetGeodeticInformation();

  friend void to_json(nlohmann::json& j, const GeraLocation& o);
  friend void from_json(const nlohmann::json& j, GeraLocation& o);

 protected:
  std::string m_LocationNumber;
  bool m_LocationNumberIsSet;
  CellGlobalId m_Cgi;
  bool m_CgiIsSet;
  RoutingAreaId m_Rai;
  bool m_RaiIsSet;
  ServiceAreaId m_Sai;
  bool m_SaiIsSet;
  LocationAreaId m_Lai;
  bool m_LaiIsSet;
  std::string m_VlrNumber;
  bool m_VlrNumberIsSet;
  std::string m_MscNumber;
  bool m_MscNumberIsSet;
  int32_t m_AgeOfLocationInformation;
  bool m_AgeOfLocationInformationIsSet;
  std::string m_UeLocationTimestamp;
  bool m_UeLocationTimestampIsSet;
  std::string m_GeographicalInformation;
  bool m_GeographicalInformationIsSet;
  std::string m_GeodeticInformation;
  bool m_GeodeticInformationIsSet;
};

}  // namespace oai::nef::model

#endif /* GeraLocation_H_ */
