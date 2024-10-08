#ifndef IRODS_PROJECT_TEMPLATE_CPP_AUTH_PLUGIN_LOGGING_CATEGORY_HPP
#define IRODS_PROJECT_TEMPLATE_CPP_AUTH_PLUGIN_LOGGING_CATEGORY_HPP

#include <irods/irods_logger.hpp>

// 1. Declare the custom category tag.
//    This structure does not need to define a body.
//    This tag allows the logger to locate data specific to the new category.
struct project_template_cpp_auth_plugin_logging_category;

// 2. Specialize the logger configuration for the new category.
//    This also defines the default configuration for the new category.
namespace irods::experimental
{
    template <>
    class log::logger_config<project_template_cpp_auth_plugin_logging_category>
    {
        // This defines the name that will appear in the log under the "log_category" key.
        // The "log_category" key defines where the message originated. Try to use a name
        // that makes it easy for administrators to determine what produced the message.
        static constexpr const char* name = "project_template_cpp_auth_plugin";

        // This is required since the fields above are private.
        // This allows the logger to access and modify the configuration.
        friend class logger<project_template_cpp_auth_plugin_logging_category>;

        // This is the current log level for the category. This also represents the initial
        // log level. Use the "set_level()" function to adjust the level.
        static inline log::level level = log::level::info;
    };
} // namespace irods::experimental

#endif //IRODS_PROJECT_TEMPLATE_CPP_AUTH_PLUGIN_LOGGING_CATEGORY_HPP
