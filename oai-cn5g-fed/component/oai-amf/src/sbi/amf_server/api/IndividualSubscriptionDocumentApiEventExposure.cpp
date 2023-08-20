/**
 * Namf_Communication
 * AMF Communication Service © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "IndividualSubscriptionDocumentApiEventExposure.h"
#include "Helpers.h"
#include "amf_config.hpp"

extern config::amf_config amf_cfg;

namespace oai {
namespace amf {
namespace api {

using namespace oai::amf::helpers;
using namespace oai::amf::model;

IndividualSubscriptionDocumentApiEventExposure::
    IndividualSubscriptionDocumentApiEventExposure(
        const std::shared_ptr<Pistache::Rest::Router>& rtr)
    : router(rtr) {}

void IndividualSubscriptionDocumentApiEventExposure::init() {
  setupRoutes();
}

void IndividualSubscriptionDocumentApiEventExposure::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Delete(
      *router,
      base + amf_cfg.sbi_api_version + "/subscriptions/:subscriptionId",
      Routes::bind(
          &IndividualSubscriptionDocumentApiEventExposure::
              delete_subscription_handler,
          this));
  Routes::Patch(
      *router,
      base + amf_cfg.sbi_api_version + "/subscriptions/:subscriptionId",
      Routes::bind(
          &IndividualSubscriptionDocumentApiEventExposure::
              modify_subscription_handler,
          this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &IndividualSubscriptionDocumentApiEventExposure::
          individual_subscription_document_api_default_handler,
      this));
}

std::pair<Pistache::Http::Code, std::string>
IndividualSubscriptionDocumentApiEventExposure::handleParsingException(
    const std::exception& ex) const noexcept {
  try {
    throw ex;
  } catch (nlohmann::detail::exception& e) {
    return std::make_pair(Pistache::Http::Code::Bad_Request, e.what());
  } catch (oai::amf::helpers::ValidationException& e) {
    return std::make_pair(Pistache::Http::Code::Bad_Request, e.what());
  }
}

std::pair<Pistache::Http::Code, std::string>
IndividualSubscriptionDocumentApiEventExposure::handleOperationException(
    const std::exception& ex) const noexcept {
  return std::make_pair(Pistache::Http::Code::Internal_Server_Error, ex.what());
}

void IndividualSubscriptionDocumentApiEventExposure::
    delete_subscription_handler(
        const Pistache::Rest::Request& request,
        Pistache::Http::ResponseWriter response) {
  try {
    // Getting the path params
    auto subscriptionId = request.param(":subscriptionId").as<std::string>();

    try {
      this->delete_subscription(subscriptionId, response);
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
void IndividualSubscriptionDocumentApiEventExposure::
    modify_subscription_handler(
        const Pistache::Rest::Request& request,
        Pistache::Http::ResponseWriter response) {
  try {
    // Getting the path params
    auto subscriptionId = request.param(":subscriptionId").as<std::string>();

    // Getting the body param

    // UNKNOWN_BASE_TYPE uNKNOWNBASETYPE;

    AmfUpdateEventOptionItem amfUpdateEventOptionItem;
    // TODO:AmfUpdateEventSubscriptionItem

    try {
      nlohmann::json::parse(request.body()).get_to(amfUpdateEventOptionItem);
      amfUpdateEventOptionItem.validate();
    } catch (std::exception& e) {
      const std::pair<Pistache::Http::Code, std::string> errorInfo =
          this->handleParsingException(e);
      response.send(errorInfo.first, errorInfo.second);
      return;
    }
    /*
        //TODO:AmfUpdateEventSubscriptionItem
        try {
            //this->modify_subscription(subscriptionId, uNKNOWNBASETYPE,
       response); } catch (Pistache::Http::HttpError &e) {
            response.send(static_cast<Pistache::Http::Code>(e.code()),
       e.what()); return; } catch (std::exception &e) { const
       std::pair<Pistache::Http::Code, std::string> errorInfo =
       this->handleOperationException(e); response.send(errorInfo.first,
       errorInfo.second); return;
        }
    */
  } catch (std::exception& e) {
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
  }
}

void IndividualSubscriptionDocumentApiEventExposure::
    individual_subscription_document_api_default_handler(
        const Pistache::Rest::Request&,
        Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace api
}  // namespace amf
}  // namespace oai
