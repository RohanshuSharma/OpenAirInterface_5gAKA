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
 * DnnSelectionMode.h
 *
 * Possible values are - VERIFIED - UE_DNN_NOT_VERIFIED - NW_DNN_NOT_VERIFIED
 */

#ifndef DnnSelectionMode_H_
#define DnnSelectionMode_H_

#include "DnnSelectionMode_anyOf.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace pcf {
namespace model {

/// <summary>
/// Possible values are - VERIFIED - UE_DNN_NOT_VERIFIED - NW_DNN_NOT_VERIFIED
/// </summary>
class DnnSelectionMode {
 public:
  DnnSelectionMode();
  virtual ~DnnSelectionMode() = default;

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

  bool operator==(const DnnSelectionMode& rhs) const;
  bool operator!=(const DnnSelectionMode& rhs) const;

  /////////////////////////////////////////////
  /// DnnSelectionMode members

  DnnSelectionMode_anyOf getValue() const;
  void setValue(DnnSelectionMode_anyOf value);
  DnnSelectionMode_anyOf::eDnnSelectionMode_anyOf getEnumValue() const;
  void setEnumValue(DnnSelectionMode_anyOf::eDnnSelectionMode_anyOf value);
  friend void to_json(nlohmann::json& j, const DnnSelectionMode& o);
  friend void from_json(const nlohmann::json& j, DnnSelectionMode& o);
  friend void to_json(nlohmann::json& j, const DnnSelectionMode_anyOf& o);
  friend void from_json(const nlohmann::json& j, DnnSelectionMode_anyOf& o);

 protected:
  DnnSelectionMode_anyOf m_value;
};

}  // namespace model
}  // namespace pcf
}  // namespace oai
#endif /* DnnSelectionMode_H_ */
