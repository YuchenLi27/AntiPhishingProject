from loguru import logger
from sklearn.ensemble import RandomForestClassifier

from machine_learning.random_forest_model import RandomForestModel
from utils.constants import CSV_ML_DATA_FILENAME


def main():
    # logger.add() : setup the environment
    logger.add("model_output/random_forest_report_{time}.log", # the update time will replace {time}
               format="{time} {level} {message}", # the format of line, level: error, info etc. msg: {string}
               level="INFO", # it is like a filter, ie. above of info level we have: warning, debug etc.
               enqueue=True) # focus on multithreading, give a queue to make sure no loss of the info. if one thread,
                            # can change to False.

    model = RandomForestModel(CSV_ML_DATA_FILENAME)
    model.generate_and_check_random_forest_performance_with_cross_validation()


if __name__ == '__main__':
    main()
