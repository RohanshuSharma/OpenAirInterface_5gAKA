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
 * AmfEventMode.h
 *
 *
 */

#ifndef AmfEventMode_H_
#define AmfEventMode_H_

#include <nlohmann/json.hpp>
#include <string>

#include "AmfEventTrigger.h"

namespace oai::nef::model {

/// <summary>
///
/// </summary>
class AmfEventMode {
 public:
  AmfEventMode();
  virtual ~AmfEventMode() = default;

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

  bool operator==(const AmfEventMode& rhs) const;
  bool operator!=(const AmfEventMode& rhs) const;

  /////////////////////////////////////////////
  /// AmfEventMode members

  /// <summary>
  ///
  /// </summary>
  AmfEventTrigger getTrigger() const;
  void setTrigger(AmfEventTrigger const& value);
  /// <summary>
  ///
  /// </summary>
  int32_t getMaxReports() const;
  void setMaxReports(int32_t const value);
  bool maxReportsIsSet() const;
  void unsetMaxReports();
  /// <summary>
  /// string with format \&quot;date-time\&quot; as defined in OpenAPI.
  /// </summary>
  std::string getExpiry() const;
  void setExpiry(std::string const& value);
  bool expiryIsSet() const;
  void unsetExpiry();

  friend void to_json(nlohmann::json& j, const AmfEventMode& o);
  friend void from_json(const nlohmann::json& j, AmfEventMode& o);

 protected:
  AmfEventTrigger m_Trigger;

  int32_t m_MaxReports;
  bool m_MaxReportsIsSet;
  std::string m_Expiry;
  bool m_ExpiryIsSet;
};

}  // namespace oai::nef::model

#endif /* AmfEventMode_H_ */
