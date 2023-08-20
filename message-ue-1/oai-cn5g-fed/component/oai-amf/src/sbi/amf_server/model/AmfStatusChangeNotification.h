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
 * AmfStatusChangeNotification.h
 *
 *
 */

#ifndef AmfStatusChangeNotification_H_
#define AmfStatusChangeNotification_H_

#include "AmfStatusInfo.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace oai {
namespace amf {
namespace model {

/// <summary>
///
/// </summary>
class AmfStatusChangeNotification {
 public:
  AmfStatusChangeNotification();
  virtual ~AmfStatusChangeNotification();

  void validate();

  /////////////////////////////////////////////
  /// AmfStatusChangeNotification members

  /// <summary>
  ///
  /// </summary>
  std::vector<AmfStatusInfo>& getAmfStatusInfoList();

  friend void to_json(nlohmann::json& j, const AmfStatusChangeNotification& o);
  friend void from_json(
      const nlohmann::json& j, AmfStatusChangeNotification& o);

 protected:
  std::vector<AmfStatusInfo> m_AmfStatusInfoList;
};

}  // namespace model
}  // namespace amf
}  // namespace oai

#endif /* AmfStatusChangeNotification_H_ */
