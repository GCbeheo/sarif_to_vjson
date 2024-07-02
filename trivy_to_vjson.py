import sys
import json
import traceback
import re

FINDING_SOURCE = "trivyConfig"

# Helper functions (mock implementations, replace with actual implementations)
def _load_json_file(filepath):
    with open(filepath, 'r') as file:
        return json.load(file)


def severity_num_to_qualitative(severity):
    return severity


def assert_trivy_severity_is_valid(severity):
    return severity


def is_ghsa_id(rule_id):
    return False


def get_github_advisory_severity_value(rule_id):
    return "High"


def extract_fixed_version(message_text):
    return "1.0.0"


def _validate_summary_field(summary, rule):
    return summary


def dict_strip(metadata):
    return metadata


def get_vuln_dict(summary, description, rule_id, raw_severity, fixed_version, issue_digest_metadata):
    return {
        "summary": summary,
        "description": description,
        "rule_id": rule_id,
        "raw_severity": raw_severity,
        "fixed_version": fixed_version,
        "metadata": issue_digest_metadata
    }


def _write_vjson_dict_file(output_name, vuln_dict_list):
    with open(output_name, 'w') as file:
        json.dump(vuln_dict_list, file, indent=2)


# Main function
def parse_trivy_config_sarif(input_filepath, affected_component, output_name):
    sarif_data = _load_json_file(input_filepath)
    issues_list = {}

    for run in sarif_data["runs"]:
        rules_list = run["tool"]["driver"]["rules"]

        for result in run["results"]:
            this_rule = rules_list[result["ruleIndex"]]
            summary = this_rule["shortDescription"]["text"]
            description = [
                this_rule["fullDescription"]["text"],
                result["message"]["text"],
            ]
            rule_id = this_rule["id"]

            raw_severity = None
            matcher = re.findall(
                r"severity:\s*(low|medium|high|critical|\S*)",
                result["message"]["text"],
                flags=re.IGNORECASE,
            )
            if (
                    "properties" in this_rule
                    and "security-severity" in this_rule["properties"]
            ):
                raw_severity = severity_num_to_qualitative(
                    this_rule["properties"]["security-severity"]
                )
            elif matcher:
                try:
                    raw_severity = assert_trivy_severity_is_valid(matcher[0])
                except:
                    print(f"Error parsing severity: {matcher[0]}")
                    traceback.print_exc()
            elif is_ghsa_id(rule_id):
                raw_severity = get_github_advisory_severity_value(rule_id)
            if not raw_severity:
                raw_severity = "High"
            raw_severity = assert_trivy_severity_is_valid(raw_severity)
            impacted_artifact = _get_affected_file_path(result["locations"])
            impacted_code_lines = _get_affected_location_lines(result["locations"])

            summary = _validate_summary_field(summary, this_rule)
            issue_key = f"{rule_id}_{impacted_artifact}"

            fixed_version = extract_fixed_version(
                message_text=f'{this_rule["fullDescription"]["text"]}\n{result["message"]["text"]}'
            )

            if issue_key not in issues_list:
                issues_list[issue_key] = {
                    "summary": summary,
                    "description": description,
                    "rule_id": rule_id,
                    "raw_severity": raw_severity,
                    "affected_component": affected_component,
                    "impacted_artifact": impacted_artifact,
                    "fixed_version": fixed_version,
                    "impacted_code_lines": [impacted_code_lines],
                }
            else:
                issues_list[issue_key]["impacted_code_lines"].append(
                    impacted_code_lines
                )

    vuln_dict_list = []

    for issue_key in issues_list:
        issue_digest_metadata = {
            "cve_id": issues_list[issue_key]["rule_id"],
            "impacted_artifact": issues_list[issue_key]["impacted_artifact"],
            "finding_source": FINDING_SOURCE,
            "affected_component": issues_list[issue_key]["affected_component"],
        }

        issue_digest_metadata = dict_strip(issue_digest_metadata)
        combined_description = [
            "\n".join(issues_list[issue_key]["description"]),
            "**Impacted artifact & locations(s):**\n- "
            + "\n- ".join(issues_list[issue_key]["impacted_code_lines"]),
        ]

        vuln_dict_list.append(
            get_vuln_dict(
                issues_list[issue_key]["summary"],
                combined_description,
                issues_list[issue_key]["rule_id"],
                issues_list[issue_key]["raw_severity"],
                issues_list[issue_key]["fixed_version"],
                issue_digest_metadata,
            )
        )

    _write_vjson_dict_file(output_name, vuln_dict_list)


def _get_affected_file_path(location_list):
    affected_file_path = ""
    for location in location_list:
        affected_file_path += location["physicalLocation"]["artifactLocation"]["uri"]
    return affected_file_path


def _get_affected_location_lines(location_list):
    affected_locations = ""
    for location in location_list:
        affected_locations += (
                location["physicalLocation"]["artifactLocation"]["uri"] + " "
        )
        if "endLine" in location["physicalLocation"]["region"]:
            affected_locations += (
                "(from Line: {AFFECTED_START} to {AFFECTED_END})".format(
                    AFFECTED_START=location["physicalLocation"]["region"]["startLine"],
                    AFFECTED_END=location["physicalLocation"]["region"]["endLine"],
                )
            )
        else:
            affected_locations += "(from Line: {AFFECTED_START})".format(
                AFFECTED_START=location["physicalLocation"]["region"]["startLine"]
            )

    return affected_locations


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 trivy_to_vjson.py <input_sarif_file> <affected_component> <output_vjson_file>")
        sys.exit(1)

    input_sarif_file = sys.argv[1]
    affected_component = sys.argv[2]
    output_vjson_file = sys.argv[3]

    parse_trivy_config_sarif(input_sarif_file, affected_component, output_vjson_file)
