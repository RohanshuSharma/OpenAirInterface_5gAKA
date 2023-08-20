/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
/**
 * Nudr_DataRepository API OpenAPI file
 * Unified Data Repository Service. © 2020, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 2.1.2
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * UsageMonitoringInformationDocumentApi.h
 *
 *
 */

#ifndef UsageMonitoringInformationDocumentApi_H_
#define UsageMonitoringInformationDocumentApi_H_

#include <pistache/http.h>
#include <pistache/http_headers.h>
#include <pistache/optional.h>
#include <pistache/router.h>

#include <string>

#include "ProblemDetails.h"
#include "UsageMonData.h"

namespace oai::udr::api {

using namespace oai::udr::model;

class UsageMonitoringInformationDocumentApi {
 public:
  UsageMonitoringInformationDocumentApi(
      std::shared_ptr<Pistache::Rest::Router>);
  virtual ~UsageMonitoringInformationDocumentApi() {}
  void init();

  const std::string base = "/nudr-dr/";

 private:
  void setupRoutes();

  void create_usage_monitoring_resource_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void delete_usage_monitoring_information_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void read_usage_monitoring_information_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void usage_monitoring_information_document_api_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  std::shared_ptr<Pistache::Rest::Router> router;

  /// <summary>
  /// Create a usage monitoring resource
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="ueId"></param>
  /// <param name="usageMonId"></param>
  /// <param name="usageMonData"></param>
  virtual void create_usage_monitoring_resource(
      const std::string& ueId, const std::string& usageMonId,
      const UsageMonData& usageMonData,
      Pistache::Http::ResponseWriter& response) = 0;

  /// <summary>
  /// Delete a usage monitoring resource
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="ueId"></param>
  /// <param name="usageMonId"></param>
  virtual void delete_usage_monitoring_information(
      const std::string& ueId, const std::string& usageMonId,
      Pistache::Http::ResponseWriter& response) = 0;

  /// <summary>
  /// Retrieve a usage monitoring resource
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="ueId"></param>
  /// <param name="usageMonId"></param>
  /// <param name="suppFeat">Supported Features (optional, default to
  /// &quot;&quot;)</param>
  virtual void read_usage_monitoring_information(
      const std::string& ueId, const std::string& usageMonId,
      const Pistache::Optional<std::string>& suppFeat,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace oai::udr::api

#endif /* UsageMonitoringInformationDocumentApi_H_ */
