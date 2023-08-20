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
 * DddStatus.h
 *
 * Possible values are - BUFFERED: The downlink data are buffered. -
 * TRANSMITTED: The downlink data are transmitted - DISCARDED: The downlink data
 * are discarded.
 */

#ifndef DddStatus_H_
#define DddStatus_H_

#include <nlohmann/json.hpp>

#include "DddStatus_anyOf.h"

namespace oai::nef::model {

/// <summary>
/// Possible values are - BUFFERED: The downlink data are buffered. -
/// TRANSMITTED: The downlink data are transmitted - DISCARDED: The downlink
/// data are discarded.
/// </summary>
class DddStatus {
 public:
  DddStatus();
  virtual ~DddStatus() = default;

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

  bool operator==(const DddStatus& rhs) const;
  bool operator!=(const DddStatus& rhs) const;

  /////////////////////////////////////////////
  /// DddStatus members

  DddStatus_anyOf getValue() const;
  void setValue(DddStatus_anyOf value);
  DddStatus_anyOf::eDddStatus_anyOf getEnumValue() const;
  void setEnumValue(DddStatus_anyOf::eDddStatus_anyOf value);
  friend void to_json(nlohmann::json& j, const DddStatus& o);
  friend void from_json(const nlohmann::json& j, DddStatus& o);
  friend void to_json(nlohmann::json& j, const DddStatus_anyOf& o);
  friend void from_json(const nlohmann::json& j, DddStatus_anyOf& o);

 protected:
  DddStatus_anyOf m_value;
};

}  // namespace oai::nef::model

#endif /* DddStatus_H_ */
