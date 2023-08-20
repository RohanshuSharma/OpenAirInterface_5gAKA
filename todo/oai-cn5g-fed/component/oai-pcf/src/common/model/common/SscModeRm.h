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
 * SscModeRm.h
 *
 *
 */

#ifndef SscModeRm_H_
#define SscModeRm_H_

#include "NullValue.h"
#include "SscMode.h"
#include <nlohmann/json.hpp>

namespace oai::model::common {

/// <summary>
///
/// </summary>
class SscModeRm {
 public:
  SscModeRm();
  virtual ~SscModeRm() = default;

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

  bool operator==(const SscModeRm& rhs) const;
  bool operator!=(const SscModeRm& rhs) const;

  /////////////////////////////////////////////
  /// SscModeRm members

  friend void to_json(nlohmann::json& j, const SscModeRm& o);
  friend void from_json(const nlohmann::json& j, SscModeRm& o);

 protected:
};

}  // namespace oai::model::common

#endif /* SscModeRm_H_ */