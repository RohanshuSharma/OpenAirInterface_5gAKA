/**
 * Nnef_SMContext
 * Nnef SMContext Service. © 2021, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.0.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * SmContextReleaseData.h
 *
 *
 */

#ifndef SmContextReleaseData_H_
#define SmContextReleaseData_H_

#include <nlohmann/json.hpp>

#include "ReleaseCause.h"

namespace oai::nef::model {

/// <summary>
///
/// </summary>
class SmContextReleaseData {
 public:
  SmContextReleaseData();
  virtual ~SmContextReleaseData() = default;

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

  bool operator==(const SmContextReleaseData& rhs) const;
  bool operator!=(const SmContextReleaseData& rhs) const;

  /////////////////////////////////////////////
  /// SmContextReleaseData members

  /// <summary>
  ///
  /// </summary>
  ReleaseCause getCause() const;
  void setCause(ReleaseCause const& value);

  friend void to_json(nlohmann::json& j, const SmContextReleaseData& o);
  friend void from_json(const nlohmann::json& j, SmContextReleaseData& o);

 protected:
  ReleaseCause m_Cause;
};

}  // namespace oai::nef::model

#endif /* SmContextReleaseData_H_ */
