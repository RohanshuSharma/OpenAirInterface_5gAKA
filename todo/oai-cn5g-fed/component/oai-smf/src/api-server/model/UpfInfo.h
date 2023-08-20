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
 * UpfInfo.h
 *
 *
 */

#ifndef UpfInfo_H_
#define UpfInfo_H_

#include "AtsssCapability.h"
#include "InterfaceUpfInfoItem.h"
#include "SnssaiUpfInfoItem.h"
#include <string>
#include "PduSessionType.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class UpfInfo {
 public:
  UpfInfo();
  virtual ~UpfInfo();

  void validate();

  /////////////////////////////////////////////
  /// UpfInfo members

  /// <summary>
  ///
  /// </summary>
  std::vector<SnssaiUpfInfoItem>& getSNssaiUpfInfoList();
  void setSNssaiUpfInfoList(std::vector<SnssaiUpfInfoItem> const& value);
  /// <summary>
  ///
  /// </summary>
  std::vector<std::string>& getSmfServingArea();
  void setSmfServingArea(std::vector<std::string> const& value);
  bool smfServingAreaIsSet() const;
  void unsetSmfServingArea();
  /// <summary>
  ///
  /// </summary>
  std::vector<InterfaceUpfInfoItem>& getInterfaceUpfInfoList();
  void setInterfaceUpfInfoList(std::vector<InterfaceUpfInfoItem> const& value);
  bool interfaceUpfInfoListIsSet() const;
  void unsetInterfaceUpfInfoList();
  /// <summary>
  ///
  /// </summary>
  bool isIwkEpsInd() const;
  void setIwkEpsInd(bool const value);
  bool iwkEpsIndIsSet() const;
  void unsetIwkEpsInd();
  /// <summary>
  ///
  /// </summary>
  std::vector<PduSessionType>& getPduSessionTypes();
  void setPduSessionTypes(std::vector<PduSessionType> const& value);
  bool pduSessionTypesIsSet() const;
  void unsetPduSessionTypes();
  /// <summary>
  ///
  /// </summary>
  AtsssCapability getAtsssCapability() const;
  void setAtsssCapability(AtsssCapability const& value);
  bool atsssCapabilityIsSet() const;
  void unsetAtsssCapability();
  /// <summary>
  ///
  /// </summary>
  bool isUeIpAddrInd() const;
  void setUeIpAddrInd(bool const value);
  bool ueIpAddrIndIsSet() const;
  void unsetUeIpAddrInd();

  friend void to_json(nlohmann::json& j, const UpfInfo& o);
  friend void from_json(const nlohmann::json& j, UpfInfo& o);

 protected:
  std::vector<SnssaiUpfInfoItem> m_SNssaiUpfInfoList;

  std::vector<std::string> m_SmfServingArea;
  bool m_SmfServingAreaIsSet;
  std::vector<InterfaceUpfInfoItem> m_InterfaceUpfInfoList;
  bool m_InterfaceUpfInfoListIsSet;
  bool m_IwkEpsInd;
  bool m_IwkEpsIndIsSet;
  std::vector<PduSessionType> m_PduSessionTypes;
  bool m_PduSessionTypesIsSet;
  AtsssCapability m_AtsssCapability;
  bool m_AtsssCapabilityIsSet;
  bool m_UeIpAddrInd;
  bool m_UeIpAddrIndIsSet;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai

#endif /* UpfInfo_H_ */
