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
 * LcsServiceAuth_anyOf.h
 *
 *
 */

#ifndef LcsServiceAuth_anyOf_H_
#define LcsServiceAuth_anyOf_H_

#include <nlohmann/json.hpp>

namespace oai::model::common {

/// <summary>
///
/// </summary>
class LcsServiceAuth_anyOf {
 public:
  LcsServiceAuth_anyOf();
  virtual ~LcsServiceAuth_anyOf() = default;

  enum class eLcsServiceAuth_anyOf {
    // To have a valid default value.
    // Avoiding name clashes with user defined
    // enum values
    INVALID_VALUE_OPENAPI_GENERATED = 0,
    LOCATION_ALLOWED_WITH_NOTIFICATION,
    LOCATION_ALLOWED_WITHOUT_NOTIFICATION,
    LOCATION_ALLOWED_WITHOUT_RESPONSE,
    LOCATION_RESTRICTED_WITHOUT_RESPONSE,
    NOTIFICATION_ONLY,
    NOTIFICATION_AND_VERIFICATION_ONLY
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

  bool operator==(const LcsServiceAuth_anyOf& rhs) const;
  bool operator!=(const LcsServiceAuth_anyOf& rhs) const;

  /////////////////////////////////////////////
  /// LcsServiceAuth_anyOf members

  LcsServiceAuth_anyOf::eLcsServiceAuth_anyOf getValue() const;
  void setValue(LcsServiceAuth_anyOf::eLcsServiceAuth_anyOf value);

  friend void to_json(nlohmann::json& j, const LcsServiceAuth_anyOf& o);
  friend void from_json(const nlohmann::json& j, LcsServiceAuth_anyOf& o);

 protected:
  LcsServiceAuth_anyOf::eLcsServiceAuth_anyOf m_value = LcsServiceAuth_anyOf::
      eLcsServiceAuth_anyOf::INVALID_VALUE_OPENAPI_GENERATED;
};

}  // namespace oai::model::common

#endif /* LcsServiceAuth_anyOf_H_ */
