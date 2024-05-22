import csv
import itertools
from collections import OrderedDict

import numpy as np
import pandas as pd

import matplotlib
import matplotlib.pyplot as plt

from loguru import logger
from scipy import interp
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.preprocessing import LabelEncoder

from utils.constants import (CSV_ML_DATA_DELIMITER, CSV_ML_DATA_QUOTE_CHAR, ML_FEATURES, ML_LABEL,
                             phish_label, legitimate_label, STRING_FEATURES)


class RandomForestModel:
    def __init__(self, input_file_name):
        matplotlib.use('Agg')
        self.input_file_name = input_file_name
        self.ml_feature = ML_FEATURES
        self.ml_label = ML_LABEL
        self.string_feature = STRING_FEATURES

    def generate_and_check_random_forest_performance_with_cross_validation(self):
        data_matrix = self.get_input_data()
        self.pre_prosee_data(data_matrix)
        selected_features = self.select_features(data_matrix)
        cv = StratifiedKFold(n_splits=5, shuffle=True)
