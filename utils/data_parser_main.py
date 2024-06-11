from loguru import logger

from data_parser import DataParser
from utils.util_functions import get_legitimate_url_list, get_phishing_url_list
from multiprocessing.pool import ThreadPool

@logger.cathc
def main():
    MAX_PARSER_THREAD = 22
    logger.add("logs/parser_{time}.log",
               format="{time} {level} {message}",
               level="INFO",
               enqueue=True)
    pool= ThreadPool(MAX_PARSER_THREAD)

    try:
        legitimate_urls = get_legitimate_url_list()
        logger.info("Start parsing data for {} legitimate urls!", len(legitimate_url_list))
        pool.map(run_parse_thread, legitimate_url_list)
    except Exception as e:
        logger.exception("Exception occurred while parsing legitimate urls")
    finally:
        pool.close()
        pool.join()
    logger.info("Completed parsing data for {} legitimate urls!", len(legitimate_url_list))
