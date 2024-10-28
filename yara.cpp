#include "include.h"

std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule) {
    genericRules.push_back({ name, rule });
}

void initializeGenericRules() {

    
    addGenericRule("Generic A", R"(
import "pe"
rule A
{
    strings:
        $a = /clicker/i ascii wide
        $b = /autoclick/i ascii wide
    condition:
        pe.is_pe and
        any of them
}
)");

    addGenericRule("Specifics A", R"(
rule sA
{
    strings:
        $a = /Exodus\.codes/i ascii wide
        $b = /slinky\.gg/i ascii wide
        $c = /slinkyhook\.dll/i ascii wide
        $d = /slinky_library\.dll/i ascii wide
        $e = /\[!\] Failed to find Vape jar/i ascii wide
        $f = /\$Vape Launcher/i ascii wide

    condition:
        pe.is_pe and
        any of them
}
)");
    // MAS
}

int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        std::vector<std::string>* matched_rules = (std::vector<std::string>*)user_data;
        matched_rules->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

void compiler_error_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {
    fprintf(stderr, "Error: %s at line %d: %s\n", file_name ? file_name : "N/A", line_number, message);
}

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules) {
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) return false;

    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        yr_finalize();
        return false;
    }

    yr_compiler_set_callback(compiler, compiler_error_callback, NULL);

    for (const auto& rule : genericRules) {
        result = yr_compiler_add_string(compiler, rule.rule.c_str(), NULL);
        if (result != 0) {
            yr_compiler_destroy(compiler);
            yr_finalize();
            return false;
        }
    }

    result = yr_compiler_get_rules(compiler, &rules);
    if (result != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        return false;
    }

    result = yr_rules_scan_file(rules, path.c_str(), 0, yara_callback, &matched_rules, 0);

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return !matched_rules.empty();
}
