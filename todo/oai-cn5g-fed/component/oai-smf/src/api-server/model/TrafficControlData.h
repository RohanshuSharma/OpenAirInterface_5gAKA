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
/*
 * TrafficControlData.h
 *
 *
 */

#ifndef TrafficControlData_H_
#define TrafficControlData_H_

#include "RedirectInformation.h"
//#include "SteeringFunctionality.h"
#include "FlowStatus.h"
#include <string>
//#include "MulticastAccessControl.h"
//#include "SteeringMode.h"
#include "RouteToLocation.h"
#include <vector>
//#include "UpPathChgEvent.h"
#include <nlohmann/json.hpp>

// TODO unsupported models are commented out
namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class TrafficControlData {
 public:
  TrafficControlData();
  virtual ~TrafficControlData() = default;

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

  bool operator==(const TrafficControlData& rhs) const;
  bool operator!=(const TrafficControlData& rhs) const;

  /////////////////////////////////////////////
  /// TrafficControlData members

  /// <summary>
  /// Univocally identifies the traffic control policy data within a PDU
  /// session.
  /// </summary>
  std::string getTcId() const;
  void setTcId(std::string const& value);
  /// <summary>
  ///
  /// </summary>
  FlowStatus getFlowStatus() const;
  void setFlowStatus(FlowStatus const& value);
  bool flowStatusIsSet() const;
  void unsetFlowStatus();
  /// <summary>
  ///
  /// </summary>
  RedirectInformation getRedirectInfo() const;
  void setRedirectInfo(RedirectInformation const& value);
  bool redirectInfoIsSet() const;
  void unsetRedirectInfo();
  /// <summary>
  ///
  /// </summary>
  std::vector<RedirectInformation> getAddRedirectInfo() const;
  void setAddRedirectInfo(std::vector<RedirectInformation> const& value);
  bool addRedirectInfoIsSet() const;
  void unsetAddRedirectInfo();
  /// <summary>
  /// Indicates whether applicat&#39;on&#39;s start or stop notification is to
  /// be muted.
  /// </summary>
  bool isMuteNotif() const;
  void setMuteNotif(bool const value);
  bool muteNotifIsSet() const;
  void unsetMuteNotif();
  /// <summary>
  /// Reference to a pre-configured traffic steering policy for downlink traffic
  /// at the SMF.
  /// </summary>
  std::string getTrafficSteeringPolIdDl() const;
  void setTrafficSteeringPolIdDl(std::string const& value);
  bool trafficSteeringPolIdDlIsSet() const;
  void unsetTrafficSteeringPolIdDl();
  /// <summary>
  /// Reference to a pre-configured traffic steering policy for uplink traffic
  /// at the SMF.
  /// </summary>
  std::string getTrafficSteeringPolIdUl() const;
  void setTrafficSteeringPolIdUl(std::string const& value);
  bool trafficSteeringPolIdUlIsSet() const;
  void unsetTrafficSteeringPolIdUl();
  /// <summary>
  /// A list of location which the traffic shall be routed to for the AF request
  /// </summary>
  std::vector<RouteToLocation> getRouteToLocs() const;
  void setRouteToLocs(std::vector<RouteToLocation> const& value);
  bool routeToLocsIsSet() const;
  void unsetRouteToLocs();
  /// <summary>
  ///
  /// </summary>
  bool isTraffCorreInd() const;
  void setTraffCorreInd(bool const value);
  bool traffCorreIndIsSet() const;
  void unsetTraffCorreInd();
  /// <summary>
  ///
  /// </summary>
  /*
  UpPathChgEvent getUpPathChgEvent() const;
  void setUpPathChgEvent(UpPathChgEvent const& value);
  bool upPathChgEventIsSet() const;
  void unsetUpPathChgEvent();
  /// <summary>
  ///
  /// </summary>
  SteeringFunctionality getSteerFun() const;
  void setSteerFun(SteeringFunctionality const& value);
  bool steerFunIsSet() const;
  void unsetSteerFun();
  /// <summary>
  ///
  /// </summary>
  SteeringMode getSteerModeDl() const;
  void setSteerModeDl(SteeringMode const& value);
  bool steerModeDlIsSet() const;
  void unsetSteerModeDl();
  /// <summary>
  ///
  /// </summary>
  SteeringMode getSteerModeUl() const;
  void setSteerModeUl(SteeringMode const& value);
  bool steerModeUlIsSet() const;
  void unsetSteerModeUl();
  /// <summary>
  ///
  /// </summary>
  MulticastAccessControl getMulAccCtrl() const;
  void setMulAccCtrl(MulticastAccessControl const& value);
  bool mulAccCtrlIsSet() const;
  void unsetMulAccCtrl();
  */
  friend void to_json(nlohmann::json& j, const TrafficControlData& o);
  friend void from_json(const nlohmann::json& j, TrafficControlData& o);

 protected:
  std::string m_TcId;

  FlowStatus m_FlowStatus;
  bool m_FlowStatusIsSet;
  RedirectInformation m_RedirectInfo;
  bool m_RedirectInfoIsSet;
  std::vector<RedirectInformation> m_AddRedirectInfo;
  bool m_AddRedirectInfoIsSet;
  bool m_MuteNotif;
  bool m_MuteNotifIsSet;
  std::string m_TrafficSteeringPolIdDl;
  bool m_TrafficSteeringPolIdDlIsSet;
  std::string m_TrafficSteeringPolIdUl;
  bool m_TrafficSteeringPolIdUlIsSet;
  std::vector<RouteToLocation> m_RouteToLocs;
  bool m_RouteToLocsIsSet;
  bool m_TraffCorreInd;
  bool m_TraffCorreIndIsSet;
  /*
  UpPathChgEvent m_UpPathChgEvent;
  bool m_UpPathChgEventIsSet;
  SteeringFunctionality m_SteerFun;
  bool m_SteerFunIsSet;
  SteeringMode m_SteerModeDl;
  bool m_SteerModeDlIsSet;
  SteeringMode m_SteerModeUl;
  bool m_SteerModeUlIsSet;
  MulticastAccessControl m_MulAccCtrl;
  bool m_MulAccCtrlIsSet;
  */
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai
#endif /* TrafficControlData_H_ */