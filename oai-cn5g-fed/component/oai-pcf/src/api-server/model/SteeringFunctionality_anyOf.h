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
 * SteeringFunctionality_anyOf.h
 *
 *
 */

#ifndef SteeringFunctionality_anyOf_H_
#define SteeringFunctionality_anyOf_H_

#include <nlohmann/json.hpp>

namespace oai {
namespace pcf {
namespace model {

/// <summary>
///
/// </summary>
class SteeringFunctionality_anyOf {
 public:
  SteeringFunctionality_anyOf();
  virtual ~SteeringFunctionality_anyOf() = default;

  enum class eSteeringFunctionality_anyOf {
    // To have a valid default value.
    // Avoiding name clashes with user defined
    // enum values
    INVALID_VALUE_OPENAPI_GENERATED = 0,
    MPTCP,
    ATSSS_LL
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

  bool operator==(const SteeringFunctionality_anyOf& rhs) const;
  bool operator!=(const SteeringFunctionality_anyOf& rhs) const;

  /////////////////////////////////////////////
  /// SteeringFunctionality_anyOf members

  SteeringFunctionality_anyOf::eSteeringFunctionality_anyOf getValue() const;
  void setValue(
      SteeringFunctionality_anyOf::eSteeringFunctionality_anyOf value);

  friend void to_json(nlohmann::json& j, const SteeringFunctionality_anyOf& o);
  friend void from_json(
      const nlohmann::json& j, SteeringFunctionality_anyOf& o);

 protected:
  SteeringFunctionality_anyOf::eSteeringFunctionality_anyOf m_value =
      SteeringFunctionality_anyOf::eSteeringFunctionality_anyOf::
          INVALID_VALUE_OPENAPI_GENERATED;
};

}  // namespace model
}  // namespace pcf
}  // namespace oai
#endif /* SteeringFunctionality_anyOf_H_ */