/// \file

#include <irods/authentication_plugin_framework.hpp>

#include <irods/irods_logger.hpp>
#include <irods/rcConnect.h>

#ifdef RODS_SERVER
#  include "irods/private/pam/project_template_cpp_plugin_logging_category.hpp"
#endif

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <string>

namespace
{
	namespace irods_auth = irods::experimental::auth;
	using log_plugin = irods::experimental::log::logger<project_template_cpp_auth_plugin_logging_category>;
} // anonymous namespace

namespace irods
{
	// This project template will implement a flow that goes like this:
	//
	//     auth_client_start   auth_client_operation   auth_client_authenticated
	//      \                  / \                     /
	//       \                /   \                   /
	// CLIENT \              /     \                 /                    CLIENT
	// --------\------------/-------\---------------/---------------------------
	// SERVER   \          /         \             /                      SERVER
	//           \        /           \           /
	//           auth_agent_start   auth_agent_operation
	//
	// An auth plugin can implement as many steps as needed to satisfy authentication requirements.
	class project_template_cpp_authentication : public irods_auth::authentication_base
	{
	  private:
		// These are the strings used to refer to the operations added for this plugin. These operation names can
		// be anything you want.
		static constexpr const char* auth_client_operation_name = "auth_client_operation";
		static constexpr const char* auth_client_authenticated_name = "auth_client_authenticated";
		static constexpr const char* auth_agent_start_name = "auth_agent_start";
		static constexpr const char* auth_agent_operation_name = "auth_agent_operation";

		// This is the string that will be used for the name of the auth scheme. Setting the auth scheme in the client
		// and server connection information is important for the server to be able to identify the type of
		// authentication used by the client.
		static constexpr const char* project_template_cpp_scheme = "project_template_cpp";

	  public:
		project_template_cpp_authentication()
		{
			// The start operation is not added here because the authentication_base class already has the start
			// operation built in. It must be implemented in the client-side plugin.

			// Other client-side operations can be added here. The only required operation is the start operation, but
			// it is a good idea to separate steps in the authentication flow into different operations.
			add_operation(auth_client_operation_name, OPERATION(rcComm_t, auth_client_operation));

			// This operation would represent wrapping up the authentication process in the client. Again, it is not
			// required to add an operation like this, but can make the flow easier to understand.
			add_operation(auth_client_authenticated_name, OPERATION(rcComm_t, auth_client_authenticated));

#ifdef RODS_SERVER
			// The plugin has client-side operations and server-side operations. Server-side operations are only
			// compiled into the server-side plugin, currently denoted by the RODS_SERVER build macro. It is only
			// required to add one server-side operation in order to authenticate with the server. However, as with the
			// client-side operations, it is a good idea to separate steps in the authentication flow into different
			// operations.

			// If your plugin requires any initialization (e.g. setting up log levels, initializing a library), it may
			// be helpful to implement a server-side start or init operation.
			add_operation(auth_agent_start_name, OPERATION(rsComm_t, auth_agent_start));

			// This operation would represent some authentication step which requires communicating with the iRODS
			// server or some centralized service which iRODS trusts for authentication (e.g. PAM).
			add_operation(auth_agent_operation_name, OPERATION(rsComm_t, auth_agent_operation));
#endif
		} // project_template_cpp_authentication constructor

	  private:
		auto auth_client_start(rcComm_t& comm, const nlohmann::json& req) -> nlohmann::json
		{
			// The auth_client_start operation is required to be implemented by the authentication_base class.

			// Some client-side initialization and decision making can happen here.

			// Consider reaching out to the server at this point to perform any initialization steps.
			auto server_req = req;
			server_req[irods_auth::next_operation] = auth_agent_start_name;

			auto resp = irods_auth::request(comm, server_req);

			// In order to advance to the next step in the flow, set the next_operation key to the name of the next
			// operation and return the JSON structure.
			resp[irods_auth::next_operation] = auth_client_operation_name;
			return resp;
		} // auth_client_start

		auto auth_client_operation(rcComm_t& comm, const nlohmann::json& req) -> nlohmann::json
		{
			// At this point, you may wish to display a prompt to the user, or the plugin can require certain keys up
			// front to provide input if you wish to avoid working with stdin and stdout.

			// The authentication plugin framework uses irods::exception to emit and handle errors, so
			// irods_auth::request will throw if any errors occur.
			auto server_req = req;
			server_req[irods_auth::next_operation] = auth_agent_operation_name;
			auto resp = irods_auth::request(comm, server_req);

			// In order to advance to the next step in the flow, set the next_operation key to the name of the next
			// operation and return the JSON structure.
			resp[irods_auth::next_operation] = auth_client_authenticated_name;
			return resp;
		} // auth_client_operation

		auto auth_client_authenticated(rcComm_t& comm, const nlohmann::json& req) -> nlohmann::json
		{
			nlohmann::json resp{req};

			// If everything completes successfully, the flow is completed and we can consider the user "logged in".
			resp[irods_auth::next_operation] = irods_auth::flow_complete;

			// The RcComm::loggedIn member indicates to client libraries that authentication has already occurred. Your
			// plugin's client-side operation should set this before returning that authentication is complete.
			comm.loggedIn = 1;

			return resp;
		} // auth_client_authenticated

#ifdef RODS_SERVER
		auto auth_agent_start(rsComm_t& comm, const nlohmann::json& req) -> nlohmann::json
		{
			// This operation can be used to initialize state in the server, whether that's with the iRODS server or a
			// service being used for this authentication.

			constexpr const char* CFG_LOG_LEVEL_CATEGORY_PROJECT_TEMPLATE_CPP_AUTH_PLUGIN_KW =
				"project_template_cpp_auth_plugin";
			log_plugin::set_level(irods::experimental::log::get_level_from_config(
				CFG_LOG_LEVEL_CATEGORY_PROJECT_TEMPLATE_CPP_AUTH_PLUGIN_KW));

			auto resp = req;

			// Set the auth scheme in the RsComm structure for the benefit of other server operations.
			if (comm.auth_scheme) {
				free(comm.auth_scheme);
			}
			comm.auth_scheme = strdup(project_template_cpp_scheme);

			// The server side operations are not required or even expected to set the next operation as the framework
			// is built on the assumption that the client-side plugin will drive the flow.

			return resp;
		} // auth_agent_start

		auto auth_agent_operation(rsComm_t& comm, const nlohmann::json& req) -> nlohmann::json
		{
			auto resp = req;

			// This can do any kinds of checks you want. For this template, we are doing the bare minimum while
			// demonstrating the capability to enable multiple steps.

			// The most important part of the server side of the plugin is to intialize the authInfo of the
			// RsComm::clientUser and RsComm::proxyUser. This is a kind of authorization which sets the privilege level
			// of the authenticated user in the RsComm. Once this is set, it determines which APIs the client is allowed
			// to invoke as this authenticated user. This is how the server knows that the user has been authenticated.

			// For this template project, we will make 3 assumptions:
			//   1. The client user and proxy user are the same (i.e. not acting on behalf of another user).
			//   2. The user is unprivileged (i.e. not a rodsadmin).
			//   3. The user's "home zone" is the local zone (i.e. not a remote user).
			comm.proxyUser.authInfo.authFlag = LOCAL_USER_AUTH;
			comm.clientUser.authInfo.authFlag = LOCAL_USER_AUTH;

			return resp;
		} // auth_agent_operation
#endif
	}; // class project_template_cpp_authentication
} // namespace irods

extern "C" auto plugin_factory(const std::string&, const std::string&) -> irods::project_template_cpp_authentication*
{
	return new irods::project_template_cpp_authentication{};
} // plugin_factory
