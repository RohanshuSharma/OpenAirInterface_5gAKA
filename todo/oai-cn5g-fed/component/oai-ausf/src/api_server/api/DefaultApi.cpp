/**
 * AUSF API
 * AUSF UE Authentication Service. © 2020, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 *file except in compliance with the License. You may obtain a copy of the
 *License at
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

#include "DefaultApi.h"
#include "Helpers.h"
#include "logger.hpp"
#include <iostream>

using namespace std;

namespace oai {
namespace ausf_server {
namespace api {

using namespace oai::ausf_server::helpers;
using namespace oai::ausf_server::model;

DefaultApi::DefaultApi(std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void DefaultApi::init() {
  setupRoutes();
}

void DefaultApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Post(
      *router, base + "/ue-authentications/:authCtxId/eap-session",
      Routes::bind(&DefaultApi::eap_auth_method_handler, this));
  Routes::Post(
      *router, base + "/rg-authentications",
      Routes::bind(&DefaultApi::rg_authentications_post_handler, this));
  Routes::Put(
      *router, base + "/ue-authentications/:authCtxId/5g-aka-confirmation",
      Routes::bind(
          &DefaultApi::
              ue_authentications_auth_ctx_id5g_aka_confirmation_put_handler,
          this));
  Routes::Post(
      *router, base + "/ue-authentications/deregister",
      Routes::bind(
          &DefaultApi::ue_authentications_deregister_post_handler, this));
  Routes::Post(
      *router, base + "/ue-authentications",
      Routes::bind(&DefaultApi::ue_authentications_post_handler, this));

  // Default handler, called when a route is not found
  router->addCustomHandler(
      Routes::bind(&DefaultApi::default_api_default_handler, this));
}

void DefaultApi::eap_auth_method_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto authCtxId = request.param(":authCtxId").as<std::string>();

  // Getting the body param

  EapSession eapSession;

  try {
    nlohmann::json::parse(request.body()).get_to(eapSession);
    this->eap_auth_method(authCtxId, eapSession, response);
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

void DefaultApi::rg_authentications_post_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the body param

  RgAuthenticationInfo rgAuthenticationInfo;

  try {
    nlohmann::json::parse(request.body()).get_to(rgAuthenticationInfo);
    this->rg_authentications_post(rgAuthenticationInfo, response);
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

void DefaultApi::ue_authentications_auth_ctx_id5g_aka_confirmation_put_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::ausf_server().info("Received 5g_aka_confirmation Request");
  // Getting the path params
  auto authCtxId = request.param(":authCtxId").as<std::string>();
  Logger::ausf_server().info(
      "5gaka confirmation received with authctxID %s", authCtxId.c_str());

  // Getting the body param

  ConfirmationData confirmationData;

  try {
    nlohmann::json::parse(request.body()).get_to(confirmationData);
    this->ue_authentications_auth_ctx_id5g_aka_confirmation_put(
        authCtxId, confirmationData, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    Logger::ausf_server().error("Bad request (Code 400)");
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (Pistache::Http::HttpError& e) {
    response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    Logger::ausf_server().error("Internal Server Error (Code 500)");
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void DefaultApi::ue_authentications_deregister_post_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the body param

  DeregistrationInfo deregistrationInfo;

  try {
    nlohmann::json::parse(request.body()).get_to(deregistrationInfo);
    this->ue_authentications_deregister_post(deregistrationInfo, response);
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

void DefaultApi::ue_authentications_post_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::ausf_server().info("Received ue_authentications_post Request");
  // Getting the body param

  AuthenticationInfo authenticationInfo;

  try {
    nlohmann::json::parse(request.body()).get_to(authenticationInfo);
    this->ue_authentications_post(authenticationInfo, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    Logger::ausf_server().error("Bad request (Code 400)");
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (Pistache::Http::HttpError& e) {
    response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    Logger::ausf_server().error("Internal Server Error (Code 500)");
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void DefaultApi::default_api_default_handler(
    const Pistache::Rest::Request&, Pistache::Http::ResponseWriter response) {
  Logger::ausf_server().info("Default API Handler");
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace api
}  // namespace ausf_server
}  // namespace oai
