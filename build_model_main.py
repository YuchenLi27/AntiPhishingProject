from loguru import logger
from sklearn.ensemble import RandomForestClassifier

from machine_learning.random_forest_model import RandomForestModel
from utils.constants import CSV_ML_DATA_FILENAME


def main():
    logger.add("model_output/random_forest_report_{time}.log",
               format="{time} {level} {message}",
               level="INFO",
               enqueue=True)

    model = RandomForestModel(CSV_ML_DATA_FILENAME)
    model.generate_and_check_random_forest_performance_with_cross_validation()


if __name__ == '__main__':
    main()
