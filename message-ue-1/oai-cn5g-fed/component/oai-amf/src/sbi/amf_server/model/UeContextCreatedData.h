/**
 * Namf_Communication
 * AMF Communication Service © 2019, 3GPP Organizational Partners (ARIB, ATIS,
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
 * UeContextCreatedData.h
 *
 *
 */

#ifndef UeContextCreatedData_H_
#define UeContextCreatedData_H_

#include "N2InfoContent.h"
#include "N2SmInformation.h"
#include "UeContext.h"
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace oai {
namespace amf {
namespace model {

/// <summary>
///
/// </summary>
class UeContextCreatedData {
 public:
  UeContextCreatedData();
  virtual ~UeContextCreatedData();

  void validate();

  /////////////////////////////////////////////
  /// UeContextCreatedData members

  /// <summary>
  ///
  /// </summary>
  UeContext getUeContext() const;
  void setUeContext(UeContext const& value);
  /// <summary>
  ///
  /// </summary>
  N2InfoContent getTargetToSourceData() const;
  void setTargetToSourceData(N2InfoContent const& value);
  /// <summary>
  ///
  /// </summary>
  std::vector<N2SmInformation>& getPduSessionList();
  /// <summary>
  ///
  /// </summary>
  std::vector<N2SmInformation>& getFailedSessionList();
  bool failedSessionListIsSet() const;
  void unsetFailedSessionList();
  /// <summary>
  ///
  /// </summary>
  std::string getSupportedFeatures() const;
  void setSupportedFeatures(std::string const& value);
  bool supportedFeaturesIsSet() const;
  void unsetSupportedFeatures();
  /// <summary>
  ///
  /// </summary>
  bool isPcfReselectedInd() const;
  void setPcfReselectedInd(bool const value);
  bool pcfReselectedIndIsSet() const;
  void unsetPcfReselectedInd();

  friend void to_json(nlohmann::json& j, const UeContextCreatedData& o);
  friend void from_json(const nlohmann::json& j, UeContextCreatedData& o);

 protected:
  UeContext m_UeContext;

  N2InfoContent m_TargetToSourceData;

  std::vector<N2SmInformation> m_PduSessionList;

  std::vector<N2SmInformation> m_FailedSessionList;
  bool m_FailedSessionListIsSet;
  std::string m_SupportedFeatures;
  bool m_SupportedFeaturesIsSet;
  bool m_PcfReselectedInd;
  bool m_PcfReselectedIndIsSet;
};

}  // namespace model
}  // namespace amf
}  // namespace oai

#endif /* UeContextCreatedData_H_ */
