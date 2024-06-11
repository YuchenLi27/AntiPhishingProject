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
        self.ml_features = ML_FEATURES
        self.ml_label = ML_LABEL
        self.string_features = STRING_FEATURES

    def generate_and_check_random_forest_performance_with_cross_validation(self):
        data_matrix = self.get_input_data()
        self.pre_process_data(data_matrix)
        selected_features = self.select_features(data_matrix)
        cv = StratifiedKFold(n_splits=5, shuffle=True)
        # strartifiedKFold: stratified sample selecting
        classifier = RandomForestClassifier(n_jobs=-1, n_estimators=50, max_features="log2", max_depth=25)
        logger.info("Training a model with {} features, feature list: {}", len(selected_features), selected_features)
        self.get_report_with_cross_validation(data_matrix, selected_features, cv, classifier)

    def get_report_with_cross_validation(self, data_matrix,features, cv, classifier):
        tprs = []
        aucs = []
        mean_fpr = np.linspace(0, 1, 350)

        accuracies = []
        precisions = []
        recalls = []
        f1_scores = []
        true_positives = []
        false_positives = []
        true_negatives = []
        false_negatives = []

        x = data_matrix[features]
        y = data_matrix[self.ml_label]

        x = x.values.astype(float)
        y = y.values.astype(float)

        fold_count = 0
        fig, ax = plt.subplots(nrows =1, mcols =1)
        importance_dict = dict()
        for train, test in cv.split(x, y):
            fold_count += 1
            logger.info("Calculate fold {}", fold_count)
            model = classifier.fit(x[train], y[train])

            for i, ele in enumerate(model.feature_importances_):
                importance = (ele / 5) + (importance_dict.get(features[i], 0) /5)
                # the value of key mapping, to gain the average value of 5 folds
                importance_dict[features[i]] = importance

            y_pred = model.predict(x[test])
            y_true = y[test]

            accuracies.append(accuracy_score(y_true, y_pred))
            precisions.append(precision_score(y_true, y_pred))
            recalls.append(recall_score(y_true, y_pred))
            f1_scores.append(f1_score(y_true, y_pred))

            cm = confusion_matrix(y_true, y_pred)
            # astype: change the data type to float
            confusion = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]
            true_negatives.append(confusion[0][0])
            false_negatives.append(confusion[1][0])
            true_positives.append(confusion[1][1])
            false_positives.append(confusion[0][1])

            # predict(): to predict the actual class
            # predict_proba(): to predict the class probabilities
            probas = model.predict_proba(x[test])
            fpr, tpr, thresholds = roc_curve(y[test], probas[:, 1])
            tprs.append(interp(mean_fpr, fpr, tpr))
            tprs[-1][0] = 0.0
            # auc(): a
            roc_auc = auc(fpr, tpr)
            aucs.append(roc_auc)
            # plt.plot() : draw points in a diagram
            plt.plot(fpr, tpr, lw=1, alpha=0.3, label="ROC fold %d (AUC = %0.2f)" % (fold_count, roc_auc))

            mean_tpr = np.mean(tprs, axis=0)
            mean_tpr[-1] = 1.0
            mean_auc = np.mean(aucs)
            plt.plot(
                mean_fpr,
                mean_tpr,
                color="b",
                label="Mean ROC (AUC = %0.2f)" % mean_auc,
                lw=1,
                alpha=0.8
            )

            graph_name = "Random Forest"
            # xlim: return tuple,  set the xlim to left/right
            plt.xlim([-0.05, 1.05])
            plt.ylim([-0.05, 1.05])
            plt.xlabel("False Positive Rate", fontsize=15)
            plt.ylabel("True Positive Rate", fontsize=15)
            plt.title("ROC of {}".format(graph_name))
            # legend: to place a legend on the axes
            plt.legend(loc="lower right")
            fig.savefig("ROC_Random_Forest.png")

            logger.info("Importance of features: ")
            ordered_importance = self.sort_dict_by_value(importance_dict)
            for key, value in ordered_importance.items():
                logger.info("{} --> {}".format(key, value))

            mean_accuracy = np.mean(accuracies)
            mean_precision = np.mean(precisions)
            mean_recall = np.mean(recalls)
            mean_f1 = np.mean(f1_scores)
            mean_tp_rate = np.mean(true_positives)
            mean_fp_rate = np.mean(false_positives)
            mean_tn_rate = np.mean(true_negatives)
            mean_fn_rate = np.mean(false_negatives)

            mean_cm = np.array([[mean_tn_rate, mean_fp_rate], [mean_fn_rate, mean_tp_rate]])
            self.plot_confusion_matrix(mean_cm, ["legitimate", "phish"], graph_name)

            logger.info("Classification reports of {}!", graph_name)
            logger.info('Mean accuracy: {}'.format(round(mean_accuracy, 2)))
            logger.info('Mean precision: {}'.format(round(mean_precision, 2)))
            logger.info('Mean recall: {}'.format(round(mean_recall, 2)))
            logger.info('Mean f1 score: {}'.format(round(mean_f1, 2)))
            logger.info('Mean TP rate: {}'.format(round(mean_tp_rate, 2)))
            logger.info('Mean FP rate: {}'.format(round(mean_fp_rate, 2)))
            logger.info('Mean TN rate: {}'.format(round(mean_tn_rate, 2)))
            logger.info('Mean FN rate: {}'.format(round(mean_fn_rate, 2)))

    def plot_confusion_matrix(self, cm, classes, graph_name, title = 'Confusion matrix', cmap= plt.cm.Blues):
            plt.figure()
            fig, ax = plt.subplots(nrows=1, ncols=1)  # draw a graph
            plt.imshow(cm, interpolation='nearest', cmap=cmap) #display data as an image
            plt.title(title)
            plt.colorbar()
            tick_marks = np.arange(len(classes))
            plt.xticks(tick_marks, classes, rotation=45) # get/ set the current tick location
            plt.yticks(tick_marks, classes)

            fmt = ".2f"
            thresh = cm.max() / 2. # /2.0 turn int to float
            for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
                plt.text(j, i, format(cm[i, j], fmt),# add text into the plot
                        horizontalalignment="center",
                        color="white" if cm[i, j] > thresh else "black")

            plt.ylabel("True label", fontsize=15)
            plt.xlabel("Predicted label", fontsize=15)
            plt.tight_layout()

            fig.savefig("Confusion_matrix_of_{}.png".format(graph_name.replace(' ', '_')))

    def sort_dict_by_value(self, d):
        """
        Fort an OrderedDict by values, from high to low
        """
        sorted_dict = OrderedDict()
        value_key = {
            value: key
            for key, value in d.items()
        }
        sorted_value = sorted(list(d.values()), reverse=True)
        for val in sorted_value:
            sorted_dict[value_key[val]] = val

        return sorted_dict

    def get_input_data(self):
        data_matrix = pd.read_csv(
            self.input_file_name,
            delimiter=CSV_ML_DATA_DELIMITER,
            quotechar=CSV_ML_DATA_QUOTE_CHAR,
            quoting=csv.QUOTE_ALL,
            skipinitialspace=True
        )

        return data_matrix

    def pre_process_data(self, data_matrix):
        for feature in self.string_features:
            self.encode_string_column(data_matrix, feature)
        logger.debug("Sample encoded input data matrix", data_matrix.head())
        self.mask_na_values(data_matrix)

        labels = data_matrix[self.ml_label]

        label_count = dict()
        for ele in labels:
            label_count[ele] = label_count.get(ele, 0) + 1
        logger.info("Number of examples: ")
        for ele in label_count:
            logger.info("Task_label {} count : {}".format(ele, label_count.get(ele)))

    def select_features(self, data_matrix):
        logger.info(" {} features in training data before selecting features", len(self.ml_features))

        selector = VarianceThreshold(0.0) # to keep the variance is non-zro variance
        selector.fit(data_matrix[self.ml_features])
        selected_feature_index = selector.get_support(indices=True)
        # get a mask, or int index of selector
        # if True, the return value will be an array of int, not a boolean
        logger.debug(
            u'Number of features {} after removing no variance data'.format(len(selected_feature_index)))

        selected_features = []
        for i in range(len(self.ml_features)):
            if i not in selected_feature_index:
                logger.debug("Removed {}".format(self.ml_features[i]))
            else:
                selected_features.append(self.ml_features[i])

        logger.info("Features selected:", selected_features)

        return selected_features

    def encode_string_column(self, data_matrix, target_column):
        data_matrix[target_column].fillna(value='missing', inplace=True)
        #fillna replaces the Null values w/ a specified value,
        # If True: the replacing is done on the current DataFrame.
        targets = data_matrix[target_column].unique()
        # to see how many unique values in a particular column, it returns the unique values
        # panda 's array math functions
        # unique() helps us get the list of the unique value,
        logger.info("Encoding column {}", target_column)
        le = LabelEncoder()
        # label certain value to certain ele
        le.fit(targets)
        # encode the targets to transform the value
        data_matrix[target_column] = le.transform(data_matrix[target_column])
        # encode the string to number

    def mask_na_values(self, data_matrix):
        data_matrix.fillna(value=-1, inplace=True)
