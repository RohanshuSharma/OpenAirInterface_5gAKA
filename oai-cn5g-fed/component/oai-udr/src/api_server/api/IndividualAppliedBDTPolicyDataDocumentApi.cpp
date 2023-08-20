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

#include "IndividualAppliedBDTPolicyDataDocumentApi.h"

#include "Helpers.h"
#include "udr_config.hpp"

extern oai::udr::config::udr_config udr_cfg;

namespace oai::udr::api {

using namespace oai::udr::helpers;
using namespace oai::udr::model;

IndividualAppliedBDTPolicyDataDocumentApi::
    IndividualAppliedBDTPolicyDataDocumentApi(
        std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void IndividualAppliedBDTPolicyDataDocumentApi::init() {
  setupRoutes();
}

void IndividualAppliedBDTPolicyDataDocumentApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Delete(
      *router,
      base + udr_cfg.nudr.api_version +
          "/application-data/bdtPolicyData/:bdtPolicyId",
      Routes::bind(
          &IndividualAppliedBDTPolicyDataDocumentApi::
              delete_individual_applied_bdt_policy_data_handler,
          this));
  Routes::Patch(
      *router,
      base + udr_cfg.nudr.api_version +
          "/application-data/bdtPolicyData/:bdtPolicyId",
      Routes::bind(
          &IndividualAppliedBDTPolicyDataDocumentApi::
              update_individual_applied_bdt_policy_data_handler,
          this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &IndividualAppliedBDTPolicyDataDocumentApi::
          individual_applied_bdt_policy_data_document_api_default_handler,
      this));
}

void IndividualAppliedBDTPolicyDataDocumentApi::
    delete_individual_applied_bdt_policy_data_handler(
        const Pistache::Rest::Request& request,
        Pistache::Http::ResponseWriter response) {
  if (!request.hasParam(":bdtPolicyId")) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request);
    return;
  }
  // Getting the path params
  auto bdtPolicyId = request.param(":bdtPolicyId").as<std::string>();

  try {
    this->delete_individual_applied_bdt_policy_data(bdtPolicyId, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (Pistache::Http::HttpError& e) {
    response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}
void IndividualAppliedBDTPolicyDataDocumentApi::
    update_individual_applied_bdt_policy_data_handler(
        const Pistache::Rest::Request& request,
        Pistache::Http::ResponseWriter response) {
  if (!request.hasParam(":bdtPolicyId")) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request);
    return;
  }
  // Getting the path params
  auto bdtPolicyId = request.param(":bdtPolicyId").as<std::string>();

  // Getting the body param

  BdtPolicyDataPatch bdtPolicyDataPatch;

  try {
    nlohmann::json::parse(request.body()).get_to(bdtPolicyDataPatch);
    this->update_individual_applied_bdt_policy_data(
        bdtPolicyId, bdtPolicyDataPatch, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (Pistache::Http::HttpError& e) {
    response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void IndividualAppliedBDTPolicyDataDocumentApi::
    individual_applied_bdt_policy_data_document_api_default_handler(
        const Pistache::Rest::Request&,
        Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace oai::udr::api
