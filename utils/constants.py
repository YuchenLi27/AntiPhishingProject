legitimate_label = "legitimate"
phish_label = "phishing"
DYNAMO_DB_RAW_DATA_TABLE_NAME = "raw_crawl_data"
DYNAMO_DB_PARSED_DATA_TABLE_NAME = "parsed_data_table"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
EMPTY_RESPONSE = "None"
URL_LIST_SIZE = 35000
CSV_ML_DATA_DELIMITER = ","
CSV_ML_DATA_QUOTE_CHAR = "|"
CSV_ML_DATA_FILENAME = "ml_model_input.csv"

# goal of ml_field_names is to write csv
ML_FIELD_NAMES = [
    # certificate extension features
    "authority_info_access", "authority_info_access_critical",
    "authority_key_identifier", "authority_key_identifier_critical",
    "basic_constraints", "basic_constraints_critical",
    "certificate_policies", "certificate_policies_critical",
    "crl_distribution_points", "crl_distribution_points_critical",
    "is_extended_validation", "is_extended_validation_critical",
    "has_subject_alt_name", "subject_alt_name_critical",
    "subject_directory_attributes", "subject_directory_attributes_critical",
    "subject_key_identifier", "subject_key_identifier_critical",
    "issuer_alt_name", "issuer_alt_name_critical",
    "key_usage", "key_usage_critical",
    "not_common_extension_count",

    # certificate issuer features
    "has_issuer_cn", "has_issuer_email", "has_issuer_l", "has_issuer_o", "has_issuer_ou", "has_issuer_st",

    # certificate subject features
    "has_subject_cn", "has_subject_email", "has_subject_l", "has_subject_o",
    "has_subject_ou", "has_subject_st",

    # certificate issuer and subject matching features
    "match_issuer_o_cn", "match_issuer_o_ou", "match_issuer_subject_c", "match_issuer_subject_cn",
    "match_subject_o_cn", "match_subject_o_ou", "match_website_altname", "match_website_issuercn",
    "match_website_subjectcn",
    "is_prohibited_issuer", "is_prohibited_subject", "is_trusted_ca",

    # certificate validation time features
    "diff_not_after_timestamp",
    "diff_not_before_notafter", "diff_not_before_timestamp",
    "has_expired",

    # certificate miscellaneous features
    "len_serial_num", "cert_version", "signature_algorithm",

    # traceroute result features
    "average_rtt", "hop_distance",

    # nmap port scan result features
    "device_type",
    "server_os",
    "open_ports_count",
    "open_port_21",
    "open_port_22",
    "open_port_23",
    "open_port_25",
    "open_port_26",
    "open_port_53",
    "open_port_80",
    "open_port_81",
    "open_port_110",
    "open_port_111",
    "open_port_113",
    "open_port_135",
    "open_port_139",
    "open_port_143",
    "open_port_179",
    "open_port_199",
    "open_port_443",
    "open_port_445",
    "open_port_465",
    "open_port_514",
    "open_port_515",
    "open_port_548",
    "open_port_554",
    "open_port_587",
    "open_port_646",
    "open_port_993",
    "open_port_995",
    "open_port_1025",
    "open_port_1026",
    "open_port_1027",
    "open_port_1433",
    "open_port_1720",
    "open_port_1723",
    "open_port_2000",
    "open_port_2001",
    "open_port_3306",
    "open_port_3389",
    "open_port_5060",
    "open_port_5666",
    "open_port_5900",
    "open_port_6001",
    "open_port_8000",
    "open_port_8008",
    "open_port_8080",
    "open_port_8443",
    "open_port_8888",
    "open_port_10000",
    "open_port_32768",
    "open_port_49152",
    "open_port_49154",

    # DNS features
    "exist_ptr_record", "ip_to_nameserver_ratio",
    "max_dns_a_ttl", "max_dns_aaaa_ttl", "max_dns_ns_ttl", "max_dns_nsa_ttl",
    "max_dns_nsaaaa_ttl", "num_unique_a_records",
    "num_unique_a_records_for_ns", "num_unique_aaaa_records", "num_unique_aaaa_records_for_ns",
    "num_unique_ns_records",
    "reverse_dns_look_up_matching",
    "whether_aaaa_record_exist_for_domain", "whether_aaaa_record_exist_for_name_servers",

    # HTTP features
    "http_different_domains_in_redirection",
    "http_redirection_count",
    "http_header_count",

    # URL lexical features
    "landing_url_ip_address_in_hostname", "landing_url_len_of_domain", "landing_url_num_of_dash",
    "landing_url_num_of_dot", "landing_url_num_of_path_token", "landing_url_num_of_slash",
    "origin_url_ip_address_in_hostname",
    "origin_url_len_of_domain", "origin_url_num_of_dash", "origin_url_num_of_dot",
    "origin_url_num_of_path_token", "origin_url_num_of_slash",

    # data row label
    "label"
]

ML_FEATURES = [
    # certificate extension features
    "authority_info_access", "authority_info_access_critical",
    "authority_key_identifier", "authority_key_identifier_critical",
    "basic_constraints", "basic_constraints_critical",
    "certificate_policies", "certificate_policies_critical",
    "crl_distribution_points", "crl_distribution_points_critical",
    "is_extended_validation", "is_extended_validation_critical",
    "has_subject_alt_name", "subject_alt_name_critical",
    "subject_directory_attributes", "subject_directory_attributes_critical",
    "subject_key_identifier", "subject_key_identifier_critical",
    "issuer_alt_name", "issuer_alt_name_critical",
    "key_usage", "key_usage_critical",
    "not_common_extension_count",

    # certificate issuer features
    "has_issuer_cn", "has_issuer_email", "has_issuer_l", "has_issuer_o", "has_issuer_ou", "has_issuer_st",

    # certificate subject features
    "has_subject_alt_name", "has_subject_cn", "has_subject_email", "has_subject_l", "has_subject_o",
    "has_subject_ou", "has_subject_st",

    # certificate issuer and subject matching features
    "match_issuer_o_cn", "match_issuer_o_ou", "match_issuer_subject_c", "match_issuer_subject_cn",
    "match_subject_o_cn", "match_subject_o_ou", "match_website_altname", "match_website_issuercn",
    "match_website_subjectcn",
    # "match_website_altname": dns name maybe different, but certificate can be assigned to
    # more than one domain name, this can help us prevert more mislabelling.
    "is_prohibited_issuer", "is_prohibited_subject", "is_trusted_ca",
    #prohibited: as we know, it is not trusted that if the certificate comes from the local net or wild card.
    # is_trusted_ca: is it from the trusted institutions?

    # certificate validation time features
    "diff_not_after_timestamp",
    "diff_not_before_notafter", "diff_not_before_timestamp",
    "has_expired",

    # certificate miscellaneous features
    "len_serial_num", "cert_version", "signature_algorithm",

    # traceroute result features
    "average_rtt", "hop_distance",
    #

    # nmap port scan result features
    "device_type",
    "server_os",
    "open_ports_count",
    "open_port_21",
    "open_port_22",
    "open_port_23",
    "open_port_25",
    "open_port_26",
    "open_port_53",
    "open_port_80",
    "open_port_81",
    "open_port_110",
    "open_port_111",
    "open_port_113",
    "open_port_135",
    "open_port_139",
    "open_port_143",
    "open_port_179",
    "open_port_199",
    "open_port_443",
    "open_port_445",
    "open_port_465",
    "open_port_514",
    "open_port_515",
    "open_port_548",
    "open_port_554",
    "open_port_587",
    "open_port_646",
    "open_port_993",
    "open_port_995",
    "open_port_1025",
    "open_port_1026",
    "open_port_1027",
    "open_port_1433",
    "open_port_1720",
    "open_port_1723",
    "open_port_2000",
    "open_port_2001",
    "open_port_3306",
    "open_port_3389",
    "open_port_5060",
    "open_port_5666",
    "open_port_5900",
    "open_port_6001",
    "open_port_8000",
    "open_port_8008",
    "open_port_8080",
    "open_port_8443",
    "open_port_8888",
    "open_port_10000",
    "open_port_32768",
    "open_port_49152",
    "open_port_49154",

    # DNS features
    "exist_ptr_record", "ip_to_nameserver_ratio",
    "max_dns_a_ttl", "max_dns_aaaa_ttl", "max_dns_ns_ttl", "max_dns_nsa_ttl",
    "max_dns_nsaaaa_ttl", "num_unique_a_records",
    "num_unique_a_records_for_ns", "num_unique_aaaa_records", "num_unique_aaaa_records_for_ns",
    "num_unique_ns_records",
    "reverse_dns_look_up_matching",
    "whether_aaaa_record_exist_for_domain", "whether_aaaa_record_exist_for_name_servers",

    # HTTP features
    "http_different_domains_in_redirection",
    "http_redirection_count",
    "http_header_count",

    # URL lexical features
    "landing_url_ip_address_in_hostname", "landing_url_len_of_domain", "landing_url_num_of_dash",
    "landing_url_num_of_dot", "landing_url_num_of_path_token", "landing_url_num_of_slash",
    "origin_url_ip_address_in_hostname",
    "origin_url_len_of_domain", "origin_url_num_of_dash", "origin_url_num_of_dot",
    "origin_url_num_of_path_token", "origin_url_num_of_slash",
]

ML_LABEL = "label" # goal of this project

# random forest only can handle num not string, convert string to num
STRING_FEATURES = [
    "signature_algorithm",
    "device_type",
    "server_os",
]
