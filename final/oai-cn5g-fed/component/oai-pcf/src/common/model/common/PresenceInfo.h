/**
 * Common Data Types
 * Common Data Types for Service Based Interfaces. © 2020, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.2.1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * PresenceInfo.h
 *
 *
 */

#ifndef PresenceInfo_H_
#define PresenceInfo_H_

#include "Ecgi.h"
#include "Ncgi.h"
#include "Tai.h"
#include <string>
#include "PresenceState.h"
#include "GlobalRanNodeId.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace oai::model::common {

/// <summary>
///
/// </summary>
class PresenceInfo {
 public:
  PresenceInfo();
  virtual ~PresenceInfo() = default;

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

  bool operator==(const PresenceInfo& rhs) const;
  bool operator!=(const PresenceInfo& rhs) const;

  /////////////////////////////////////////////
  /// PresenceInfo members

  /// <summary>
  ///
  /// </summary>
  std::string getPraId() const;
  void setPraId(std::string const& value);
  bool praIdIsSet() const;
  void unsetPraId();
  /// <summary>
  ///
  /// </summary>
  std::string getAdditionalPraId() const;
  void setAdditionalPraId(std::string const& value);
  bool additionalPraIdIsSet() const;
  void unsetAdditionalPraId();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::PresenceState getPresenceState() const;
  void setPresenceState(oai::model::common::PresenceState const& value);
  bool presenceStateIsSet() const;
  void unsetPresenceState();
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::Tai> getTrackingAreaList() const;
  void setTrackingAreaList(std::vector<oai::model::common::Tai> const& value);
  bool trackingAreaListIsSet() const;
  void unsetTrackingAreaList();
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::Ecgi> getEcgiList() const;
  void setEcgiList(std::vector<oai::model::common::Ecgi> const& value);
  bool ecgiListIsSet() const;
  void unsetEcgiList();
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::Ncgi> getNcgiList() const;
  void setNcgiList(std::vector<oai::model::common::Ncgi> const& value);
  bool ncgiListIsSet() const;
  void unsetNcgiList();
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::GlobalRanNodeId> getGlobalRanNodeIdList()
      const;
  void setGlobalRanNodeIdList(
      std::vector<oai::model::common::GlobalRanNodeId> const& value);
  bool globalRanNodeIdListIsSet() const;
  void unsetGlobalRanNodeIdList();
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::GlobalRanNodeId> getGlobaleNbIdList() const;
  void setGlobaleNbIdList(
      std::vector<oai::model::common::GlobalRanNodeId> const& value);
  bool globaleNbIdListIsSet() const;
  void unsetGlobaleNbIdList();

  friend void to_json(nlohmann::json& j, const PresenceInfo& o);
  friend void from_json(const nlohmann::json& j, PresenceInfo& o);

 protected:
  std::string m_PraId;
  bool m_PraIdIsSet;
  std::string m_AdditionalPraId;
  bool m_AdditionalPraIdIsSet;
  oai::model::common::PresenceState m_PresenceState;
  bool m_PresenceStateIsSet;
  std::vector<oai::model::common::Tai> m_TrackingAreaList;
  bool m_TrackingAreaListIsSet;
  std::vector<oai::model::common::Ecgi> m_EcgiList;
  bool m_EcgiListIsSet;
  std::vector<oai::model::common::Ncgi> m_NcgiList;
  bool m_NcgiListIsSet;
  std::vector<oai::model::common::GlobalRanNodeId> m_GlobalRanNodeIdList;
  bool m_GlobalRanNodeIdListIsSet;
  std::vector<oai::model::common::GlobalRanNodeId> m_GlobaleNbIdList;
  bool m_GlobaleNbIdListIsSet;
};

}  // namespace oai::model::common

#endif /* PresenceInfo_H_ */
