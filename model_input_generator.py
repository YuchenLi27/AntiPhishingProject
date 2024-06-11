import csv

from loguru import logger

from database.dynamodb_storage import DynamodbStorage
from utils.constants import DYNAMO_DB_PARSED_DATA_TABLE_NAME, ML_FIELD_NAMES, CSV_ML_DATA_DELIMITER, \
    CSV_ML_DATA_QUOTE_CHAR, CSV_ML_DATA_FILENAME, ML_LABEL, legitimate_label


class ModelInputGenerator:
    def __init__(self):
        logger.add("logs/data_generator_{time}.log",
                   format="{time} {level} {message}",
                   level="INFO",
                   enqueue=True)
        self.dynamodb_storage = DynamodbStorage(DYNAMO_DB_PARSED_DATA_TABLE_NAME)

    def generate_csv_data(self):
        logger.info("Start generating csv data input file for ML model")
        open_port_feature_prefix = "open_port"
        with open(CSV_ML_DATA_DELIMITER, " a+") as output_file:
            logger.info("Initialized csv writer with field header as {}", ML_FIELD_NAMES)
            csv_writer = csv.DictWriter(output_file, ML_FIELD_NAMES,
                                        delimiter=CSV_ML_DATA_DELIMITER,
                                        quotechar=CSV_ML_DATA_QUOTE_CHAR,
                                        quoting=csv.QUOTE_MINIMAL)

            csv_writer.writeheader()
            last_evaluated_key = None
            scan_complete = False
            while scan_complete is False:
                response = self.dynamodb_storage.scan_table(lastEvaluatedKey=last_evaluated_key)
                last_evaluated_key = response.get['LastEvaluatedKey']

                if not last_evaluated_key:
                    scan_complete = True

                for item in response["Items"]:
                    logger.debug("Processing item {}", item)
                    ml_feature_dict = dict()
                    self.build_port_feature(ml_feature_dict, item)
                    for field_name in ML_FIELD_NAMES:
                        if field_name == ML_LABEL:
                            ml_feature_dict[field_name] = 0 if item[field_name] == legitimate_label[field_name] else 1
                        elif field_name.startswith(open_port_feature_prefix):
                            continue
                        else:
                            ml_feature_dict[field_name] = item[field_name]
                    logger.info("Generated a row of feature for url {} as {}", item["url"], ml_feature_dict)
                    csv_writer.writerow(ml_feature_dict)
                del response
        logger.info("Finished generating csv data input file")

    def build_port_feature(self, ml_feature_dict, item):
        port_list = item["open_ports"]
        ml_feature_dict["open_ports_count"] = len(port_list)

        # for each of the top 50 ports scanned by nmap
        # construct a binary feature with the open/close status of the port
        # 1 if the port is open (in the list)
        # 0 if the port is not open (not in the list)
        ml_feature_dict["open_port_21"] = 1 if 21 in port_list else 0
        ml_feature_dict["open_port_22"] = 1 if 22 in port_list else 0
        ml_feature_dict["open_port_23"] = 1 if 23 in port_list else 0
        ml_feature_dict["open_port_25"] = 1 if 25 in port_list else 0
        ml_feature_dict["open_port_26"] = 1 if 26 in port_list else 0
        ml_feature_dict["open_port_53"] = 1 if 53 in port_list else 0
        ml_feature_dict["open_port_80"] = 1 if 80 in port_list else 0
        ml_feature_dict["open_port_81"] = 1 if 81 in port_list else 0
        ml_feature_dict["open_port_110"] = 1 if 110 in port_list else 0
        ml_feature_dict["open_port_111"] = 1 if 111 in port_list else 0
        ml_feature_dict["open_port_113"] = 1 if 113 in port_list else 0
        ml_feature_dict["open_port_135"] = 1 if 135 in port_list else 0
        ml_feature_dict["open_port_139"] = 1 if 139 in port_list else 0
        ml_feature_dict["open_port_143"] = 1 if 143 in port_list else 0
        ml_feature_dict["open_port_179"] = 1 if 179 in port_list else 0
        ml_feature_dict["open_port_199"] = 1 if 199 in port_list else 0
        ml_feature_dict["open_port_443"] = 1 if 443 in port_list else 0
        ml_feature_dict["open_port_445"] = 1 if 445 in port_list else 0
        ml_feature_dict["open_port_465"] = 1 if 465 in port_list else 0
        ml_feature_dict["open_port_514"] = 1 if 514 in port_list else 0
        ml_feature_dict["open_port_515"] = 1 if 515 in port_list else 0
        ml_feature_dict["open_port_548"] = 1 if 548 in port_list else 0
        ml_feature_dict["open_port_554"] = 1 if 554 in port_list else 0
        ml_feature_dict["open_port_587"] = 1 if 587 in port_list else 0
        ml_feature_dict["open_port_646"] = 1 if 646 in port_list else 0
        ml_feature_dict["open_port_993"] = 1 if 993 in port_list else 0
        ml_feature_dict["open_port_995"] = 1 if 995 in port_list else 0
        ml_feature_dict["open_port_1025"] = 1 if 1025 in port_list else 0
        ml_feature_dict["open_port_1026"] = 1 if 1026 in port_list else 0
        ml_feature_dict["open_port_1027"] = 1 if 1027 in port_list else 0
        ml_feature_dict["open_port_1433"] = 1 if 1433 in port_list else 0
        ml_feature_dict["open_port_1720"] = 1 if 1720 in port_list else 0
        ml_feature_dict["open_port_1723"] = 1 if 1723 in port_list else 0
        ml_feature_dict["open_port_2000"] = 1 if 2000 in port_list else 0
        ml_feature_dict["open_port_2001"] = 1 if 2001 in port_list else 0
        ml_feature_dict["open_port_3306"] = 1 if 3306 in port_list else 0
        ml_feature_dict["open_port_3389"] = 1 if 3389 in port_list else 0
        ml_feature_dict["open_port_5060"] = 1 if 5060 in port_list else 0
        ml_feature_dict["open_port_5666"] = 1 if 5666 in port_list else 0
        ml_feature_dict["open_port_5900"] = 1 if 5900 in port_list else 0
        ml_feature_dict["open_port_6001"] = 1 if 6001 in port_list else 0
        ml_feature_dict["open_port_8000"] = 1 if 8000 in port_list else 0
        ml_feature_dict["open_port_8008"] = 1 if 8008 in port_list else 0
        ml_feature_dict["open_port_8080"] = 1 if 8080 in port_list else 0
        ml_feature_dict["open_port_8443"] = 1 if 8443 in port_list else 0
        ml_feature_dict["open_port_8888"] = 1 if 8888 in port_list else 0
        ml_feature_dict["open_port_10000"] = 1 if 10000 in port_list else 0
        ml_feature_dict["open_port_32768"] = 1 if 32768 in port_list else 0
        ml_feature_dict["open_port_49152"] = 1 if 49152 in port_list else 0
        ml_feature_dict["open_port_49154"] = 1 if 49154 in port_list else 0


if __name__ == '__main__':
    ModelInputGenerator().generate_csv_data()
