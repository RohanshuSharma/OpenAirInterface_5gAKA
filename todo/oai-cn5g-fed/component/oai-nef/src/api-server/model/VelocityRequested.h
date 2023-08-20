/**
 * 3gpp-monitoring-event
 * API for Monitoring Event. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.2.0-alpha.4
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * VelocityRequested.h
 *
 *
 */

#ifndef VelocityRequested_H_
#define VelocityRequested_H_

#include <nlohmann/json.hpp>

#include "VelocityRequested_anyOf.h"

namespace oai::nef::model {

/// <summary>
///
/// </summary>
class VelocityRequested {
 public:
  VelocityRequested();
  virtual ~VelocityRequested() = default;

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

  bool operator==(const VelocityRequested& rhs) const;
  bool operator!=(const VelocityRequested& rhs) const;

  /////////////////////////////////////////////
  /// VelocityRequested members

  VelocityRequested_anyOf getValue() const;
  void setValue(VelocityRequested_anyOf value);
  VelocityRequested_anyOf::eVelocityRequested_anyOf getEnumValue() const;
  void setEnumValue(VelocityRequested_anyOf::eVelocityRequested_anyOf value);
  friend void to_json(nlohmann::json& j, const VelocityRequested& o);
  friend void from_json(const nlohmann::json& j, VelocityRequested& o);
  friend void to_json(nlohmann::json& j, const VelocityRequested_anyOf& o);
  friend void from_json(const nlohmann::json& j, VelocityRequested_anyOf& o);

 protected:
  VelocityRequested_anyOf m_value;
};

}  // namespace oai::nef::model

#endif /* VelocityRequested_H_ */
