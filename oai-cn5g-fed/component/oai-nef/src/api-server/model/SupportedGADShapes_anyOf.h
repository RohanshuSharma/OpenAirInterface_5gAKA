/**
 * 3gpp-mo-lcs-notify
 * API for UE updated location information notification. © 2021, 3GPP
 * Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights
 * reserved.
 *
 * The version of the OpenAPI document: 1.0.1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * SupportedGADShapes_anyOf.h
 *
 *
 */

#ifndef SupportedGADShapes_anyOf_H_
#define SupportedGADShapes_anyOf_H_

#include <nlohmann/json.hpp>

namespace oai::nef::model {

/// <summary>
///
/// </summary>
class SupportedGADShapes_anyOf {
 public:
  SupportedGADShapes_anyOf();
  virtual ~SupportedGADShapes_anyOf() = default;

  enum class eSupportedGADShapes_anyOf {
    // To have a valid default value.
    // Avoiding name clashes with user defined
    // enum values
    INVALID_VALUE_OPENAPI_GENERATED = 0,
    POINT,
    POINT_UNCERTAINTY_CIRCLE,
    POINT_UNCERTAINTY_ELLIPSE,
    POLYGON,
    POINT_ALTITUDE,
    POINT_ALTITUDE_UNCERTAINTY,
    ELLIPSOID_ARC
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

  bool operator==(const SupportedGADShapes_anyOf& rhs) const;
  bool operator!=(const SupportedGADShapes_anyOf& rhs) const;

  /////////////////////////////////////////////
  /// SupportedGADShapes_anyOf members

  SupportedGADShapes_anyOf::eSupportedGADShapes_anyOf getValue() const;
  void setValue(SupportedGADShapes_anyOf::eSupportedGADShapes_anyOf value);

  friend void to_json(nlohmann::json& j, const SupportedGADShapes_anyOf& o);
  friend void from_json(const nlohmann::json& j, SupportedGADShapes_anyOf& o);

 protected:
  SupportedGADShapes_anyOf::eSupportedGADShapes_anyOf m_value =
      SupportedGADShapes_anyOf::eSupportedGADShapes_anyOf::
          INVALID_VALUE_OPENAPI_GENERATED;
};

}  // namespace oai::nef::model

#endif /* SupportedGADShapes_anyOf_H_ */