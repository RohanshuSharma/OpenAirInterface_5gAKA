/**
 * NSSF NSSAI Availability
 * NSSF NSSAI Availability Service. © 2021, 3GPP Organizational Partners (ARIB,
 * ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.4
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "SubscriptionIDDocumentApi.h"
#include "Helpers.h"
#include "nssf_config.hpp"

extern nssf::nssf_config nssf_cfg;

namespace oai {
namespace nssf_server {
namespace api {

using namespace oai::nssf_server::helpers;
using namespace oai::nssf_server::model;

const std::string SubscriptionIDDocumentApi::base = "/nnssf-nssaiavailability/";

SubscriptionIDDocumentApi::SubscriptionIDDocumentApi(
    const std::shared_ptr<Pistache::Rest::Router>& rtr)
    : router(rtr) {}

void SubscriptionIDDocumentApi::init() {
  setupRoutes();
}

void SubscriptionIDDocumentApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Patch(
      *router,
      base + nssf_cfg.sbi_api_version +
          "/nssai-availability/subscriptions/:subscriptionId",
      Routes::bind(
          &SubscriptionIDDocumentApi::
              n_ssai_availability_sub_modify_patch_handler,
          this));
  Routes::Delete(
      *router, base + "/nssai-availability/subscriptions/:subscriptionId",
      Routes::bind(
          &SubscriptionIDDocumentApi::n_ssai_availability_unsubscribe_handler,
          this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &SubscriptionIDDocumentApi::subscription_id_document_api_default_handler,
      this));
}

std::pair<Pistache::Http::Code, std::string>
SubscriptionIDDocumentApi::handleParsingException(
    const std::exception& ex) const noexcept {
  try {
    throw;
  } catch (nlohmann::detail::exception& e) {
    return std::make_pair(Pistache::Http::Code::Bad_Request, e.what());
    // } catch (oai::nssf_server::helpers::ValidationException &e) {
    //     return std::make_pair(Pistache::Http::Code::Bad_Request, e.what());
  } catch (std::exception& e) {
    return std::make_pair(
        Pistache::Http::Code::Internal_Server_Error, e.what());
  }
}

std::pair<Pistache::Http::Code, std::string>
SubscriptionIDDocumentApi::handleOperationException(
    const std::exception& ex) const noexcept {
  return std::make_pair(Pistache::Http::Code::Internal_Server_Error, ex.what());
}

void SubscriptionIDDocumentApi::n_ssai_availability_sub_modify_patch_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  try {
    // Getting the path params
    auto subscriptionId = request.param(":subscriptionId").as<std::string>();

    // Getting the body param
    std::vector<PatchItem> patchItem;

    // Getting the header params
    auto contentEncoding = request.headers().tryGetRaw("Content-Encoding");

    try {
      nlohmann::json::parse(request.body()).get_to(patchItem);
      // patchItem.validate();
    } catch (std::exception& e) {
      const std::pair<Pistache::Http::Code, std::string> errorInfo =
          this->handleParsingException(e);
      response.send(errorInfo.first, errorInfo.second);
      return;
    }

    try {
      this->n_ssai_availability_sub_modify_patch(
          subscriptionId, patchItem, contentEncoding, response);
    } catch (Pistache::Http::HttpError& e) {
      response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
      return;
    } catch (std::exception& e) {
      const std::pair<Pistache::Http::Code, std::string> errorInfo =
          this->handleOperationException(e);
      response.send(errorInfo.first, errorInfo.second);
      return;
    }

  } catch (std::exception& e) {
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
  }
}
void SubscriptionIDDocumentApi::n_ssai_availability_unsubscribe_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  try {
    // Getting the path params
    auto subscriptionId = request.param(":subscriptionId").as<std::string>();

    try {
      this->n_ssai_availability_unsubscribe(subscriptionId, response);
    } catch (Pistache::Http::HttpError& e) {
      response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
      return;
    } catch (std::exception& e) {
      const std::pair<Pistache::Http::Code, std::string> errorInfo =
          this->handleOperationException(e);
      response.send(errorInfo.first, errorInfo.second);
      return;
    }

  } catch (std::exception& e) {
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
  }
}

void SubscriptionIDDocumentApi::subscription_id_document_api_default_handler(
    const Pistache::Rest::Request&, Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace api
}  // namespace nssf_server
}  // namespace oai
