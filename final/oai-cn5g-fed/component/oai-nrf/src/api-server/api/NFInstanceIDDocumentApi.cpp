/**
 * NRF NFManagement Service
 * NRF NFManagement Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "NFInstanceIDDocumentApi.h"
#include "Helpers.h"
#include "nrf_config.hpp"
#include "logger.hpp"

extern std::unique_ptr<oai::config::nrf::nrf_config> nrf_cfg;

namespace oai {
namespace nrf {
namespace api {

using namespace oai::nrf::helpers;
using namespace oai::nrf::model;

NFInstanceIDDocumentApi::NFInstanceIDDocumentApi(
    std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void NFInstanceIDDocumentApi::init() {
  setupRoutes();
}

void NFInstanceIDDocumentApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Delete(
      *router,
      base + nrf_cfg->local().get_sbi().get_api_version() +
          "/nf-instances/:nfInstanceID",
      Routes::bind(
          &NFInstanceIDDocumentApi::deregister_nf_instance_handler, this));
  Routes::Get(
      *router,
      base + nrf_cfg->local().get_sbi().get_api_version() +
          "/nf-instances/:nfInstanceID",
      Routes::bind(&NFInstanceIDDocumentApi::get_nf_instance_handler, this));
  Routes::Put(
      *router,
      base + nrf_cfg->local().get_sbi().get_api_version() +
          "/nf-instances/:nfInstanceID",
      Routes::bind(
          &NFInstanceIDDocumentApi::register_nf_instance_handler, this));
  Routes::Patch(
      *router,
      base + nrf_cfg->local().get_sbi().get_api_version() +
          "/nf-instances/:nfInstanceID",
      Routes::bind(&NFInstanceIDDocumentApi::update_nf_instance_handler, this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &NFInstanceIDDocumentApi::nf_instance_id_document_api_default_handler,
      this));
}

void NFInstanceIDDocumentApi::deregister_nf_instance_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto nfInstanceID = request.param(":nfInstanceID").as<std::string>();

  try {
    this->deregister_nf_instance(nfInstanceID, response);
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
void NFInstanceIDDocumentApi::get_nf_instance_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto nfInstanceID = request.param(":nfInstanceID").as<std::string>();

  try {
    this->get_nf_instance(nfInstanceID, response);
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
void NFInstanceIDDocumentApi::register_nf_instance_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto nfInstanceID = request.param(":nfInstanceID").as<std::string>();

  // Getting the body param

  NFProfile nFProfile;

  // Getting the header params
  auto contentEncoding = request.headers().tryGetRaw("Content-Encoding");

  try {
    nlohmann::json::parse(request.body()).get_to(nFProfile);
    this->register_nf_instance(
        nfInstanceID, nFProfile, contentEncoding, response);
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
void NFInstanceIDDocumentApi::update_nf_instance_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  // Getting the path params
  auto nfInstanceID = request.param(":nfInstanceID").as<std::string>();

  // Getting the body param
  std::vector<PatchItem> patchItem;

  try {
    nlohmann::json::parse(request.body()).get_to(patchItem);
    this->update_nf_instance(nfInstanceID, patchItem, response);
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

void NFInstanceIDDocumentApi::nf_instance_id_document_api_default_handler(
    const Pistache::Rest::Request&, Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace api
}  // namespace nrf
}  // namespace oai
