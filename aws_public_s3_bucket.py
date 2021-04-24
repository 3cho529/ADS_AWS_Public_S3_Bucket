import json
from collections.abc import Mapping
from functools import reduce


def deep_get(dictionary: dict, *keys, default=None):
    """Safe method to get value of nested dictionary
    Reference: by https://stackoverflow.com/questions/25833613/safe-method-to-get-value-of-nested-dictionary
    """
    return reduce(
        lambda d, key: d.get(key, default) if isinstance(d, Mapping) else default, keys, dictionary
    )

# Logic for detecting public bucket via GUI
def gui_rule(event):
	event_flag = False
	if event.get('eventName') == "PutBucketAcl":
		PUBLIC_URI_GUI_1 = "http://acs.amazonaws.com/groups/global/AllUsers"
		PUBLIC_URI_GUI_2 = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

		list_grant_dict = deep_get(event, "requestParameters", "AccessControlPolicy", "AccessControlList", "Grant")
		if list_grant_dict != None:
			for grant_dict in list_grant_dict:
				if deep_get(grant_dict, "Grantee", "URI") in [PUBLIC_URI_GUI_1, PUBLIC_URI_GUI_2]:
					event_flag = True
					break					
	return (event_flag)

# Logic for detecting public bucket via CLI
def cli_rule(event):
	event_flag = False
	if event.get('eventName') == "PutBucketAcl":
		PUBLIC_URI_CLI_1 = "uri=http://acs.amazonaws.com/groups/global/AllUsers"
		PUBLIC_URI_CLI_2 = "uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

		if deep_get(event, "requestParameters", "accessControlList","x-amz-grant-read-acp") in [PUBLIC_URI_CLI_1, PUBLIC_URI_CLI_2]:
			event_flag = True
		if deep_get(event, "requestParameters", "accessControlList","x-amz-grant-write") in [PUBLIC_URI_CLI_1, PUBLIC_URI_CLI_2]:
			event_flag = True
		if deep_get(event, "requestParameters", "accessControlList","x-amz-grant-write-acp") in [PUBLIC_URI_CLI_1, PUBLIC_URI_CLI_2]:
			event_flag = True
		if deep_get(event, "requestParameters", "accessControlList","x-amz-grant-full-control") in [PUBLIC_URI_CLI_1, PUBLIC_URI_CLI_2]:
			event_flag = True	 				
	return (event_flag)		 

# Defines message for the analyst
def title(event):
    return (
        "An AWS S3 bucket was made public. Review details below and follow response actions. \n"
        f"AWS Account: {deep_get(event, 'userIdentity', 'accountId')} \n"
        f"Bucket Name: {deep_get(event, 'requestParameters', 'bucketName', default='<UNKNOWN_BUCKET>')}"
        # Additional fields to be added for context to the analyst for example, permission.
    )


def main():

	# Parsing multiple JSON objects from a file
	# https://pynative.com/python-parse-multiple-json-objects-from-file/
	CloudTrail_Events_List = []
	with open('/home/echo/Documents/ADS_AWS_Public_S3_Bucket/aws_cloudtrail_events.json') as f:
	    for cloudtrailEvent in f:
	        eventDict = json.loads(cloudtrailEvent)
	        CloudTrail_Events_List.append(eventDict)

	event_count=0

	for event in CloudTrail_Events_List:

		if gui_rule(event) == True:
			event_count+=1
			print(title(event))
			print("Bucket was made public via the Console / GUI.")
		if cli_rule(event) == True:
			event_count+=1
			print(title(event))
			print("Bucket was made public via the CLI.")

	print(f"{event_count} out of {len(CloudTrail_Events_List)} events triggered the public bucket detection.")

if __name__ == "__main__":
	main()