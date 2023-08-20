/**
 * NSSF NS Selection
 * NSSF Network Slice Selection Service. © 2021, 3GPP Organizational Partners
 * (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 2.1.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * SliceInfoForRegistration.h
 *
 *
 */

#ifndef SliceInfoForRegistration_H_
#define SliceInfoForRegistration_H_

#include "AllowedNssai.h"
#include "MappingOfSnssai.h"
#include "Snssai.h"
#include "SubscribedSnssai.h"
#include <nlohmann/json.hpp>
#include <vector>

namespace oai {
namespace amf {
namespace model {

/// <summary>
///
/// </summary>
class SliceInfoForRegistration {
 public:
  SliceInfoForRegistration();
  virtual ~SliceInfoForRegistration() = default;

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

  bool operator==(const SliceInfoForRegistration& rhs) const;
  bool operator!=(const SliceInfoForRegistration& rhs) const;

  /////////////////////////////////////////////
  /// SliceInfoForRegistration members

  /// <summary>
  ///
  /// </summary>
  std::vector<SubscribedSnssai> getSubscribedNssai() const;
  void setSubscribedNssai(std::vector<SubscribedSnssai> const& value);
  bool subscribedNssaiIsSet() const;
  void unsetSubscribedNssai();
  /// <summary>
  ///
  /// </summary>
  AllowedNssai getAllowedNssaiCurrentAccess() const;
  void setAllowedNssaiCurrentAccess(AllowedNssai const& value);
  bool allowedNssaiCurrentAccessIsSet() const;
  void unsetAllowedNssaiCurrentAccess();
  /// <summary>
  ///
  /// </summary>
  AllowedNssai getAllowedNssaiOtherAccess() const;
  void setAllowedNssaiOtherAccess(AllowedNssai const& value);
  bool allowedNssaiOtherAccessIsSet() const;
  void unsetAllowedNssaiOtherAccess();
  /// <summary>
  ///
  /// </summary>
  std::vector<Snssai> getSNssaiForMapping() const;
  void setSNssaiForMapping(std::vector<Snssai> const& value);
  bool sNssaiForMappingIsSet() const;
  void unsetSNssaiForMapping();
  /// <summary>
  ///
  /// </summary>
  std::vector<Snssai> getRequestedNssai() const;
  void setRequestedNssai(std::vector<Snssai> const& value);
  bool requestedNssaiIsSet() const;
  void unsetRequestedNssai();
  /// <summary>
  ///
  /// </summary>
  bool isDefaultConfiguredSnssaiInd() const;
  void setDefaultConfiguredSnssaiInd(bool const value);
  bool defaultConfiguredSnssaiIndIsSet() const;
  void unsetDefaultConfiguredSnssaiInd();
  /// <summary>
  ///
  /// </summary>
  std::vector<MappingOfSnssai> getMappingOfNssai() const;
  void setMappingOfNssai(std::vector<MappingOfSnssai> const& value);
  bool mappingOfNssaiIsSet() const;
  void unsetMappingOfNssai();
  /// <summary>
  ///
  /// </summary>
  bool isRequestMapping() const;
  void setRequestMapping(bool const value);
  bool requestMappingIsSet() const;
  void unsetRequestMapping();

  friend void to_json(nlohmann::json& j, const SliceInfoForRegistration& o);
  friend void from_json(const nlohmann::json& j, SliceInfoForRegistration& o);

 protected:
  std::vector<SubscribedSnssai> m_SubscribedNssai;
  bool m_SubscribedNssaiIsSet;
  AllowedNssai m_AllowedNssaiCurrentAccess;
  bool m_AllowedNssaiCurrentAccessIsSet;
  AllowedNssai m_AllowedNssaiOtherAccess;
  bool m_AllowedNssaiOtherAccessIsSet;
  std::vector<Snssai> m_SNssaiForMapping;
  bool m_SNssaiForMappingIsSet;
  std::vector<Snssai> m_RequestedNssai;
  bool m_RequestedNssaiIsSet;
  bool m_DefaultConfiguredSnssaiInd;
  bool m_DefaultConfiguredSnssaiIndIsSet;
  std::vector<MappingOfSnssai> m_MappingOfNssai;
  bool m_MappingOfNssaiIsSet;
  bool m_RequestMapping;
  bool m_RequestMappingIsSet;
};

}  // namespace model
}  // namespace amf
}  // namespace oai

#endif /* SliceInfoForRegistration_H_ */