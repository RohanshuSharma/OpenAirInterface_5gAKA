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
 * AuthenticationUPUDocumentApi.h
 *
 *
 */

#ifndef AuthenticationUPUDocumentApi_H_
#define AuthenticationUPUDocumentApi_H_

#include <pistache/http.h>
#include <pistache/http_headers.h>
#include <pistache/optional.h>
#include <pistache/router.h>

#include <string>

#include "UpuData.h"

namespace oai::udr::api {

using namespace oai::udr::model;

class AuthenticationUPUDocumentApi {
 public:
  AuthenticationUPUDocumentApi(std::shared_ptr<Pistache::Rest::Router>);
  virtual ~AuthenticationUPUDocumentApi() {}
  void init();

  const std::string base = "/nudr-dr/";

 private:
  void setupRoutes();

  void create_authentication_upu_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void query_auth_upu_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void authentication_upu_document_api_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  std::shared_ptr<Pistache::Rest::Router> router;

  /// <summary>
  /// To store the UPU acknowledgement information of a UE
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="ueId">UE id</param>
  /// <param name="supportedFeatures">Supported Features (optional, default to
  /// &quot;&quot;)</param> <param name="upuData"> (optional)</param>
  virtual void create_authentication_upu(
      const std::string& ueId,
      const Pistache::Optional<std::string>& supportedFeatures,
      const UpuData& upuData, Pistache::Http::ResponseWriter& response) = 0;

  /// <summary>
  /// Retrieves the UPU acknowledgement information of a UE
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="ueId">UE id</param>
  /// <param name="supportedFeatures">Supported Features (optional, default to
  /// &quot;&quot;)</param>
  virtual void query_auth_upu(
      const std::string& ueId,
      const Pistache::Optional<std::string>& supportedFeatures,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace oai::udr::api

#endif /* AuthenticationUPUDocumentApi_H_ */
