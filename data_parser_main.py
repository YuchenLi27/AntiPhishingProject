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
    pool = ThreadPool(MAX_PARSER_THREAD)

    try:
        legitimate_url_list = get_legitimate_url_list()
        logger.info("Start parsing data for {} legitimate urls!", len(legitimate_url_list))
        pool.map(run_parse_thread, legitimate_url_list)
        # pool.map() would automatically execute the function with inputs in the legitimate_url_list
        # while maintain a ThreadPool size of MAX_CRAWLER_THREAD
        # So this would internally help us limit the number of threads got executed simultaneously
    except Exception as e:
        logger.exception("Exception occurred while parsing legitimate urls")
    finally:
        pool.close()
        pool.join()
    logger.info("Completed parsing data for {} legitimate urls!", len(legitimate_url_list))


    pool = ThreadPool(processes=MAX_PARSER_THREAD)

    try:
        phishing_url_list = get_phishing_url_list()
        logger.info("Start parsing data for {} phishing urls!", len(phishing_url_list))
        # use pool.map() would automatically execute the function with inputs in the legitimate_url_list
        # while maintain a ThreadPool size of MAX_CRAWLER_THREAD
        # So this would internally help us limit the number of threads got executed simultaneously
        pool.map(run_parse_thread, phishing_url_list)
        # run_parse_thread is the fun we want all phishing_url_list to run
    except Exception as e:
        logger.exception("Exception occurred while parsing phishing urls")
    finally:
        pool.close()
        pool.join()

    logger.info("Completed parsing data for {} phishing urls!", len(phishing_url_list))

def run_parse_thread(url):
    # use a new DataCollector instance each time to prevent data collision or race condition
    # between different threads which would collapse the data
    # although creating new instance each time is expensive
    data_parser = DataParser()
    data_parser.parse(url)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
