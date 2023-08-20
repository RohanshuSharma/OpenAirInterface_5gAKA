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
/*
 * AnalyticsEventFilter.h
 *
 *
 */

#ifndef AnalyticsEventFilter_H_
#define AnalyticsEventFilter_H_

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "ExceptionId.h"
#include "ExpectedAnalyticsType.h"
#include "ExpectedUeBehaviourData.h"
#include "LocationArea5G.h"
#include "NetworkPerfType.h"
#include "QosRequirement.h"
#include "Snssai.h"

namespace oai::nef::model {

/// <summary>
///
/// </summary>
class AnalyticsEventFilter {
 public:
  AnalyticsEventFilter();
  virtual ~AnalyticsEventFilter() = default;

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

  bool operator==(const AnalyticsEventFilter& rhs) const;
  bool operator!=(const AnalyticsEventFilter& rhs) const;

  /////////////////////////////////////////////
  /// AnalyticsEventFilter members

  /// <summary>
  ///
  /// </summary>
  LocationArea5G getLocArea() const;
  void setLocArea(LocationArea5G const& value);
  bool locAreaIsSet() const;
  void unsetLocArea();
  /// <summary>
  ///
  /// </summary>
  std::string getDnn() const;
  void setDnn(std::string const& value);
  bool dnnIsSet() const;
  void unsetDnn();
  /// <summary>
  ///
  /// </summary>
  std::vector<NetworkPerfType> getNwPerfTypes() const;
  void setNwPerfTypes(std::vector<NetworkPerfType> const& value);
  bool nwPerfTypesIsSet() const;
  void unsetNwPerfTypes();
  /// <summary>
  ///
  /// </summary>
  std::vector<std::string> getAppIds() const;
  void setAppIds(std::vector<std::string> const& value);
  bool appIdsIsSet() const;
  void unsetAppIds();
  /// <summary>
  ///
  /// </summary>
  std::vector<ExceptionId> getExcepIds() const;
  void setExcepIds(std::vector<ExceptionId> const& value);
  bool excepIdsIsSet() const;
  void unsetExcepIds();
  /// <summary>
  ///
  /// </summary>
  ExpectedAnalyticsType getExptAnaType() const;
  void setExptAnaType(ExpectedAnalyticsType const& value);
  bool exptAnaTypeIsSet() const;
  void unsetExptAnaType();
  /// <summary>
  ///
  /// </summary>
  ExpectedUeBehaviourData getExptUeBehav() const;
  void setExptUeBehav(ExpectedUeBehaviourData const& value);
  bool exptUeBehavIsSet() const;
  void unsetExptUeBehav();
  /// <summary>
  ///
  /// </summary>
  Snssai getSnssai() const;
  void setSnssai(Snssai const& value);
  bool snssaiIsSet() const;
  void unsetSnssai();
  /// <summary>
  ///
  /// </summary>
  QosRequirement getQosReq() const;
  void setQosReq(QosRequirement const& value);
  bool qosReqIsSet() const;
  void unsetQosReq();

  friend void to_json(nlohmann::json& j, const AnalyticsEventFilter& o);
  friend void from_json(const nlohmann::json& j, AnalyticsEventFilter& o);

 protected:
  LocationArea5G m_LocArea;
  bool m_LocAreaIsSet;
  std::string m_Dnn;
  bool m_DnnIsSet;
  std::vector<NetworkPerfType> m_NwPerfTypes;
  bool m_NwPerfTypesIsSet;
  std::vector<std::string> m_AppIds;
  bool m_AppIdsIsSet;
  std::vector<ExceptionId> m_ExcepIds;
  bool m_ExcepIdsIsSet;
  ExpectedAnalyticsType m_ExptAnaType;
  bool m_ExptAnaTypeIsSet;
  ExpectedUeBehaviourData m_ExptUeBehav;
  bool m_ExptUeBehavIsSet;
  Snssai m_Snssai;
  bool m_SnssaiIsSet;
  QosRequirement m_QosReq;
  bool m_QosReqIsSet;
};

}  // namespace oai::nef::model

#endif /* AnalyticsEventFilter_H_ */