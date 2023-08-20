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
 * GlobalRanNodeId.h
 *
 *
 */

#ifndef GlobalRanNodeId_H_
#define GlobalRanNodeId_H_

#include <string>
#include "GNbId.h"
#include "PlmnId.h"
#include <nlohmann/json.hpp>

namespace oai::model::common {

/// <summary>
///
/// </summary>
class GlobalRanNodeId {
 public:
  GlobalRanNodeId();
  virtual ~GlobalRanNodeId() = default;

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

  bool operator==(const GlobalRanNodeId& rhs) const;
  bool operator!=(const GlobalRanNodeId& rhs) const;

  /////////////////////////////////////////////
  /// GlobalRanNodeId members

  /// <summary>
  ///
  /// </summary>
  oai::model::common::PlmnId getPlmnId() const;
  void setPlmnId(oai::model::common::PlmnId const& value);
  /// <summary>
  ///
  /// </summary>
  std::string getN3IwfId() const;
  void setN3IwfId(std::string const& value);
  bool n3IwfIdIsSet() const;
  void unsetN3IwfId();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::GNbId getGNbId() const;
  void setGNbId(oai::model::common::GNbId const& value);
  bool gNbIdIsSet() const;
  void unsetGNbId();
  /// <summary>
  ///
  /// </summary>
  std::string getNgeNbId() const;
  void setNgeNbId(std::string const& value);
  bool ngeNbIdIsSet() const;
  void unsetNgeNbId();
  /// <summary>
  ///
  /// </summary>
  std::string getWagfId() const;
  void setWagfId(std::string const& value);
  bool wagfIdIsSet() const;
  void unsetWagfId();
  /// <summary>
  ///
  /// </summary>
  std::string getTngfId() const;
  void setTngfId(std::string const& value);
  bool tngfIdIsSet() const;
  void unsetTngfId();
  /// <summary>
  ///
  /// </summary>
  std::string getNid() const;
  void setNid(std::string const& value);
  bool nidIsSet() const;
  void unsetNid();
  /// <summary>
  ///
  /// </summary>
  std::string getENbId() const;
  void setENbId(std::string const& value);
  bool eNbIdIsSet() const;
  void unsetENbId();

  friend void to_json(nlohmann::json& j, const GlobalRanNodeId& o);
  friend void from_json(const nlohmann::json& j, GlobalRanNodeId& o);

 protected:
  oai::model::common::PlmnId m_PlmnId;

  std::string m_N3IwfId;
  bool m_N3IwfIdIsSet;
  oai::model::common::GNbId m_GNbId;
  bool m_GNbIdIsSet;
  std::string m_NgeNbId;
  bool m_NgeNbIdIsSet;
  std::string m_WagfId;
  bool m_WagfIdIsSet;
  std::string m_TngfId;
  bool m_TngfIdIsSet;
  std::string m_Nid;
  bool m_NidIsSet;
  std::string m_ENbId;
  bool m_ENbIdIsSet;
};

}  // namespace oai::model::common

#endif /* GlobalRanNodeId_H_ */
