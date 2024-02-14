from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException


config.load_config()
api = client.CoreV1Api()
