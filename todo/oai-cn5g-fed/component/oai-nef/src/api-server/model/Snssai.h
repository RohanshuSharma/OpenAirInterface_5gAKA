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
 * Snssai.h
 *
 *
 */

#ifndef Snssai_H_
#define Snssai_H_

#include <nlohmann/json.hpp>
#include <string>

namespace oai::nef::model {

/// <summary>
///
/// </summary>
class Snssai {
 public:
  Snssai();
  virtual ~Snssai() = default;

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

  bool operator==(const Snssai& rhs) const;
  bool operator!=(const Snssai& rhs) const;

  /////////////////////////////////////////////
  /// Snssai members

  /// <summary>
  ///
  /// </summary>
  int32_t getSst() const;
  void setSst(int32_t const value);
  /// <summary>
  ///
  /// </summary>
  std::string getSd() const;
  void setSd(std::string const& value);
  bool sdIsSet() const;
  void unsetSd();

  friend void to_json(nlohmann::json& j, const Snssai& o);
  friend void from_json(const nlohmann::json& j, Snssai& o);

 protected:
  int32_t m_Sst;

  std::string m_Sd;
  bool m_SdIsSet;
};

}  // namespace oai::nef::model

#endif /* Snssai_H_ */
