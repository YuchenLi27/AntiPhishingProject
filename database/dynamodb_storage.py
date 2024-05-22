import boto3
import simplejson as json
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from loguru import logger

import decimal
from boto3.dynamodb.types import DYNAMODB_CONTEXT

class DynamoDBStorage:
    def __init__(self,dynamodb_table_name):
        DYNAMODB_CONTEXT.traps[decimal.Inexact] = 0
        DYNAMODB_CONTEXT.traps[decimal.Rounded] = 0

        self.dynamodb_resource = boto3.resource('dynamodb', region_name='us-east-2')
        self.table = self.dynamodb_resource.Table(dynamodb_table_name)
    def store_item(self,data):
        logger.info("Attempt to store item in DynamoDB: {}", data)
        try:
            self.table.put_item(Item=data)
            logger.info("Item stored in DynamoDB")
        except Exception as e:
            try:
                logger.exception("Put item failed with first attempt, retry once on it")
                self.table.put_item(Item=data)
                logger.info("Item stored in DynamoDB will retry", json.dumps(data))
            except Exception as e:
                logger.exception("Put item retry failed. Ignore the item")
    def check_existence(self, url):
        items = self.get_item(url)
        if items:
            return True
        else:
            return False
    def get_item(self, url):
        try:
            response = self.table.query(KeyConditionExpression=Key('url').eq(url))
        except ClientError as e:
            return None
        return response['Items']

    def scan_table(self, last_evaluated_key):
        if last_evaluated_key:
            return self.table.scan(ExclusiveStartKey=last_evaluated_key)
        else:
            return self.table.scan()

