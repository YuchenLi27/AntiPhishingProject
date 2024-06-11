import gc

from loguru import logger

from data_collector import DataCollector
from utils.util_functions import get_legitimate_url_list, get_phishing_url_list
from multiprocessing.pool import ThreadPool
from utils.constants import legitimate_label, phish_label

@logger.catch
def main():
    MAX_CRAWLER_THREAD = 22
    logger.info("logs/crawler_{time}.log",
                format="{time} {level}{message}",
                level="INFO",
                enqueue=True)
    pool = ThreadPool(processes=MAX_CRAWLER_THREAD)
    #

    try:
        phishing_url_list = get_phishing_url_list()
        phishing_url_labels = [phish_label] * len(phishing_url_list)

        logger.info("Start crawl data for {} phishing urls!", len(phishing_url_list))
        pool.starmap(run_crawl_thread, zip(phishing_url_list, phishing_url_labels))
        # use pool.starmap() would automatically execute the function with inputs in the legitimate_url_list
        # while maintain a ThreadPool size of MAX_CRAWLER_THREAD
        # So this would internally help us limit the number of threads got executed simultaneously

    except Exception:
        logger.exception("Crawl phishing urls threadpool exception")
    finally:
        pool.close()
        pool.join()

    logger.info("Completed crawl data for {} phishing urls!", len(phishing_url_list))
    pool = ThreadPool(processes=MAX_CRAWLER_THREAD)

    try:
        legitimate_url_list = get_legitimate_url_list()
        legitimate_url_labels = [legitimate_label] * len(legitimate_url_list)
        logger.info("Start crawl data for {} legitimate urls!", len(legitimate_url_list))

        pool.starmap(run_crawl_thread, zip(legitimate_url_list, legitimate_url_labels))
    except Exception:
        logger.exception("Crawl legitimate urls threadpool exception")
    finally:
        pool.close()
        pool.join()

    logger.info("Completed crawl data for {} legitimate urls!", len(legitimate_url_list))


def run_crawl_thread(url, label):
    # use a new DataCollector instance each time to prevent data collision or race condition
    # between different threads which would collapse the data
    # although creating new instance each time is expensive
    data_collector = DataCollector()
    data_collector.run_crawl(url, label)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()





