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

#include "SMFRegistrationDocumentApiImpl.h"

#include "logger.hpp"
#include "udr_app.hpp"

namespace oai::udr::api {

using namespace oai::udr::model;

SMFRegistrationDocumentApiImpl::SMFRegistrationDocumentApiImpl(
    std::shared_ptr<Pistache::Rest::Router> rtr, udr_app* udr_app_inst,
    std::string address)
    : SMFRegistrationDocumentApi(rtr),
      m_udr_app(udr_app_inst),
      m_address(address) {}

void SMFRegistrationDocumentApiImpl::create_smf_context_non3gpp(
    const std::string& ueId, const int32_t& pduSessionId,
    const SmfRegistration& smfRegistration,
    Pistache::Http::ResponseWriter& response) {
  nlohmann::json response_data = {};
  Pistache::Http::Code code    = {};
  long http_code               = 0;

  m_udr_app->handle_create_smf_context_non_3gpp(
      ueId, pduSessionId, smfRegistration, response_data, http_code);

  code = static_cast<Pistache::Http::Code>(http_code);
  Logger::udr_server().debug("HTTP Response code %d.\n", (int) code);
  response.send(code, response_data.dump().c_str());
}
void SMFRegistrationDocumentApiImpl::delete_smf_context(
    const std::string& ueId, const int32_t& pduSessionId,
    Pistache::Http::ResponseWriter& response) {
  nlohmann::json response_data = {};
  Pistache::Http::Code code    = {};
  long http_code               = 0;

  m_udr_app->handle_delete_smf_context(
      ueId, pduSessionId, response_data, http_code);

  code = static_cast<Pistache::Http::Code>(http_code);
  Logger::udr_server().debug("HTTP Response code %d.\n", (int) code);
  // content type
  response.headers().add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType("application/json"));
  response.send(code, response_data.dump().c_str());
}
void SMFRegistrationDocumentApiImpl::query_smf_registration(
    const std::string& ueId, const int32_t& pduSessionId,
    const Pistache::Optional<std::vector<std::string>>& fields,
    const Pistache::Optional<std::string>& supportedFeatures,
    Pistache::Http::ResponseWriter& response) {
  nlohmann::json response_data = {};
  Pistache::Http::Code code    = {};
  long http_code               = 0;

  m_udr_app->handle_query_smf_registration(
      ueId, pduSessionId, response_data, http_code);

  code = static_cast<Pistache::Http::Code>(http_code);
  Logger::udr_server().debug("HTTP Response code %d.\n", (int) code);
  // content type
  response.headers().add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType("application/json"));
  response.send(code, response_data.dump().c_str());
}

}  // namespace oai::udr::api
