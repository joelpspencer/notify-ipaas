# ==========================================================================================
# Process an OCI notifications for Alarms (not general events such as instance stopped)
#  and send the message to CG iPaaS
# ==========================================================================================
# Copyright Capgemini 2023
# joel.spencer@capgemini.com
# michael.lehman@capgemini.com
# ==========================================================================================
# This code is provided as an example OCI function for Capgemini customers, and may be
# modified as required for their use.
# This code is provided as-is. Capgemini makes no warrenties or guarentees regarding the 
# operation, performance, security, or risks of using this code.
# It is the sole responsibility of the recipient and user of the function to verify it's 
# fitness for purpose, and to make any modifications required for the proper functioning of 
# the code.
# ==========================================================================================
# Setup container with vpc, subnet, nat gateway, service gateway
# Allow the Oracle Services on the subnet list and service gateway
# Add route for Oracle services
#
# Setup dynamic group
# ALL {resource.type = 'fnfunc', resource.compartment.id = 'ocid1.tenancy.oc1..aaa...o7vhq'}
# 
# Setup IAM Policy
# Allow dynamic-group myfunctions to use secret-family in tenancy
# ==========================================================================================
import io
import json
import base64
import json
import requests
import oci
import fields
from oci.key_management.models import DecryptDataDetails
from fdk import response
# if function fails with no module 'nnn', add nnn to the requirements.txt file to include in docker build

#--------------------------------------------------------------------------------------------
def get_secret(secret_id):
    try:
        # Many OCI library examples show the config being retrieved from a file, which won't work in the FN enviornment  
        # passing an empty config and the signer is required to authenticate to the vault (and other similar scenarios)
        signer = oci.auth.signers.get_resource_principals_signer()
        secrets_client = oci.secrets.SecretsClient({}, signer=signer)
        
        # https://docs.oracle.com/en-us/iaas/tools/python/2.104.3/api/secrets/client/oci.secrets.SecretsClient.html?highlight=get_secret_bundle#oci.secrets.SecretsClient.get_secret_bundle
        secret_content = secrets_client.get_secret_bundle(secret_id).data.secret_bundle_content.content.encode('utf-8')
        return base64.b64decode(secret_content).decode("utf-8")
    except (Exception, ValueError) as ex:
        print("ERROR: Retreiving secret bundle", ex, flush=True)
        # do not re-raise.. allow caller to decide what to do

#--------------------------------------------------------------------------------------------
def get_oauth_token(oauth_token_url, client_id, client_secret, grant_type="client_credentials"):
    # an example of this flow: https://curity.io/resources/learn/oauth-client-credentials-flow/
    # show calls with (select client credentials): https://oauth.tools/ 
    access_token = ""
    response = requests.post(
        oauth_token_url,
        data={"grant_type": grant_type},
        auth=(client_id, client_secret)
    )
    try:
        access_token = response.json()["access_token"]
        if response.status_code == 200:
           return response.json()["access_token"]
        else:
            print("ERROR: OAuth call failed: ", response.status_code, response.content, flush=True)
            raise Exception("OAuth call failed: " + response.status_code + ": " + response.content)
    except (Exception, ValueError) as ex:
        print("ERROR: OAuth call failed: ", ex, flush=True) 
        raise ex


#--------------------------------------------------------------------------------------------
def post_to_ipaas(ipaas_url, messageID, payload, oauth_token):
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + oauth_token
    }
    try:
        response = requests.post(url=ipaas_url, data=json.dumps(payload), headers=headers, allow_redirects=False)
        if response.status_code >= 200 and response.status_code < 300:
            print("INFO: Message passed to iPaaS - " + messageID , flush=True)
        else:
            print("ERROR: iPaaS webhook failed: ", str(response.status_code), response.content, flush=True)
            raise Exception("iPaaS webhook failed: " + str(response.status_code) + ": " + response.text)
    except (Exception, ValueError) as ex:
        print("ERROR: Exceptioun caught calling iPaaS webhook: ", ex, flush=True) 
        raise ex

#--------------------------------------------------------------------------------------------
def handler(ctx, data: io.BytesIO = None):
    # Notification overview:
    # https://docs.oracle.com/en-us/iaas/Content/Notification/Concepts/notificationoverview.htm
    # Notification example:
    # https://github.com/oracle-samples/oracle-functions-samples/blob/master/samples/oci-ons-compute-shape-increase-python/func.py
    # Alarm message format:
    # https://docs.oracle.com/en-us/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#MessageFormat
    # Alarm message example:
    # https://docs.oracle.com/en-us/iaas/Content/Monitoring/alarm-message-examples.htm#top

    
    config = {}
    debug = False
    oauth_token_url = ""
    oauth_client_id = ""
    oauth_client_secret_id = ""
    oauth_client_secret = ""

    alarm_msg = {}
    func_response = ""

    # these variables are left in this case to match the iPaaS system & documentation for consistency
    ipaas_url = ""
    topic = ""
    applicationId = ""
    companyName = ""
    fullDescription = ""
    shortDescription = ""
    impact = ""
    impactedCi = ""
    urgency = ""
    externalSystemTicketId = ""
    templateName = ""
    customerShortname = ""
    ipAddress = ""
    systemPlatform = ""
    alertType = ""
    memoryThreshold = ""
    cpuThreshold = ""
    diskName = ""
    serviceName = ""

    try:
        # For Config details, 
        # See https://blogs.oracle.com/developers/post/working-with-http-in-oracle-functions-using-the-fn-project-python-fdk
        config = dict(ctx.Config())
        oauth_token_url = config["oauth_token_url"]
        oauth_client_id = config["oauth_client_id"]
        oauth_client_secret_id =  config["oauth_client_secret_id"]
        ipaas_url = config["ipaas_url"]
        templateName = config["templateName"] # this is the template for the body of the ticket in ServiceNow.. blank will use the raw format passed
        applicationId = config ["applicationId"]
        topic = config["topic"]
        companyName = config["companyName"]
        customerShortname = config["customerShortname"]
    except (Exception, ValueError) as ex:
        print("ERROR: Could not get required Config values: ", ex, flush=True)
        raise ex
    
    try:
        if config["debug"] == "true":
            debug = True
        else:
            debug = False
    except:
        debug = False

    try:    
        oauth_client_secret = get_secret(oauth_client_secret_id)
    except (Exception, ValueError) as ex:
        print("ERROR: Could not retreive oauth client secret: ", ex, flush=True)
        raise ex

    try:
        oauth_token = get_oauth_token(oauth_token_url, oauth_client_id, oauth_client_secret)        
    except (Exception, ValueError) as ex:
        print("ERROR: Exception caught retrieving OAuth token: ", ex, flush=True)
        raise ex
    
    try:
        systemPlatform = config["systemPlatform"]
        if not systemPlatform or systemPlatform.strip() == "":
            systemPlatform = "OCI"
    except:
        systemPlatform = "OCI"

    # for oracle alarm field format, see: https://docs.oracle.com/en-us/iaas/Content/Monitoring/alarm-message-format.htm#top

    alarm_msg = json.loads(data.getvalue())
    if debug: print(f"INFO: alarm message: {alarm_msg}", flush=True)
    shortDescription = alarm_msg["title"]
    fullDescription = alarm_msg['body'] + "; " + alarm_msg["alarmMetaData"][0]["alarmSummary"] + "  " + alarm_msg["alarmMetaData"][0]["alarmUrl"]
    
    #this assumes that "split messages per metric stream" is enabled in the alarm.. otherwise only the first CI will be noted
    #(1 notificiation per resource/CI)
    if "resourceDisplayName" in alarm_msg["alarmMetaData"][0]["dimensions"][0]:
        impactedCi = alarm_msg["alarmMetaData"][0]["dimensions"][0]["resourceDisplayName"] 
    elif "resourceName" in alarm_msg["alarmMetaData"][0]["dimensions"][0]:
        impactedCi = alarm_msg["alarmMetaData"][0]["dimensions"][0]["resourceName"]
    elif "lbName" in alarm_msg["alarmMetaData"][0]["dimensions"][0]:
        impactedCi = alarm_msg["alarmMetaData"][0]["dimensions"][0]["lbName"] 
    else:
        impactedCi = "unknown"

    fullDescription = "ImpactedCi: " + impactedCi + "; " + alarm_msg['body'] + "; " + \
        alarm_msg["alarmMetaData"][0]["alarmSummary"] + "; " + \
        alarm_msg["alarmMetaData"][0]["alarmUrl"] + "; " + \
        json.dumps(alarm_msg["alarmMetaData"][0]["dimensions"][0])

    urgency = fields.urgency[alarm_msg["severity"]]
    impact = fields.impact[alarm_msg["severity"]]
    externalSystemTicketId = alarm_msg["dedupeKey"]
    ipAddress = ""          #not available without code to look it up for specific alarm types
    alertType = alarm_msg["type"]
    memoryThreshold = ""    # not available without code to look it up for specific alarm types
    cpuThreshold = ""       # not available without code to look it up for specific alarm types
    diskName = ""           # not available without code to look it up for specific alarm types
    serviceName = ""        # not available without code to look it up for specific alarm types

    topic = f"cn/TFMC/de/oracletosplnkna/ic/{impactedCi}/tn/{templateName}/cs/TFMC/sp/{systemPlatform}/at/{alertType}"
    if debug: print(f"INFO: topic: {topic}", flush=True)

    alarm_payload = {
        "body": {
            "companyName": companyName,
            "fullDescription": fullDescription,
            "shortDescription": shortDescription,
            "impact": impact,
            "impactedCi": impactedCi,
            "urgency":  urgency,
            "externalSystemTicketId": externalSystemTicketId,
            "templateName": templateName,
            "customerShortname": customerShortname,
            "ipAddress": ipAddress,
            "systemPlatform": systemPlatform,
            "alertType": alertType,
            "memoryThreshold": memoryThreshold,
            "cpuThreshold": cpuThreshold,
            "diskName": diskName,
            "serviceName": serviceName
        },
        "header": {
            "topic": topic,
            "applicationId": applicationId
        }
    }

    if debug: print(f"INFO: alarm_payload: {alarm_payload}", flush=True)

    post_to_ipaas(ipaas_url, externalSystemTicketId, alarm_payload, oauth_token)
    func_response = "Notification Sent to iPaas for dedupeKey: " + alarm_msg["dedupeKey"]
    
    return response.Response(
        ctx, 
        response_data=func_response,
        headers={"Content-Type": "application/json"}
    )