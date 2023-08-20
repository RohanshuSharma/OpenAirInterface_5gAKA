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
 * ChangeType_anyOf.h
 *
 *
 */

#ifndef ChangeType_anyOf_H_
#define ChangeType_anyOf_H_

#include <nlohmann/json.hpp>

namespace oai::model::common {

/// <summary>
///
/// </summary>
class ChangeType_anyOf {
 public:
  ChangeType_anyOf();
  virtual ~ChangeType_anyOf() = default;

  enum class eChangeType_anyOf {
    // To have a valid default value.
    // Avoiding name clashes with user defined
    // enum values
    INVALID_VALUE_OPENAPI_GENERATED = 0,
    ADD,
    MOVE,
    REMOVE,
    REPLACE
  };

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

  bool operator==(const ChangeType_anyOf& rhs) const;
  bool operator!=(const ChangeType_anyOf& rhs) const;

  /////////////////////////////////////////////
  /// ChangeType_anyOf members

  ChangeType_anyOf::eChangeType_anyOf getValue() const;
  void setValue(ChangeType_anyOf::eChangeType_anyOf value);

  friend void to_json(nlohmann::json& j, const ChangeType_anyOf& o);
  friend void from_json(const nlohmann::json& j, ChangeType_anyOf& o);

 protected:
  ChangeType_anyOf::eChangeType_anyOf m_value =
      ChangeType_anyOf::eChangeType_anyOf::INVALID_VALUE_OPENAPI_GENERATED;
};

}  // namespace oai::model::common

#endif /* ChangeType_anyOf_H_ */
