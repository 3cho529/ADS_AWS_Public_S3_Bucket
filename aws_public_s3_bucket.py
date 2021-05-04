# Tested with Python 3.9.4

import json
# importing Mapping and reduce functions to define a deep_get function
from collections.abc import Mapping
from functools import reduce

# deep_get function gets the value from a nested dictionary created from the JSON object
def deep_get(dictionary: dict, *keys, default=None):
    """Safe method to get value of nested dictionary
    Reference: by https://stackoverflow.com/questions/25833613/safe-method-to-get-value-of-nested-dictionary
    """
    return reduce(
        lambda d, key: d.get(key, default) if isinstance(d, Mapping) else default, keys, dictionary
    )

# Future enhancement
# Convert PUBLIC_URI to a global variable by adding string matching


# Logic for detecting public bucket via console
# Function takes a dictionary as input
def gui_rule(event):
	event_flag = False # default 
	# Define logic for turning event_flag to true
	if event.get('eventName') == "PutBucketAcl":
		# URIs of interest
		PUBLIC_URI_GUI_1 = "http://acs.amazonaws.com/groups/global/AllUsers"
		PUBLIC_URI_GUI_2 = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
		# Obtaining value of nested key "Grant" in event dictionary by providing its path  
		# Value is a list of dictionaries
		list_grant_dict = deep_get(event, "requestParameters", "AccessControlPolicy", "AccessControlList", "Grant")
		if list_grant_dict != None: # list not empty
			for grant_dict in list_grant_dict: # loop through the list of dictionaries until URIs of interest matched
				# nested key of URI match
				if deep_get(grant_dict, "Grantee", "URI") in [PUBLIC_URI_GUI_1, PUBLIC_URI_GUI_2]:
					event_flag = True
					break # first URI match exits the for loop					
	return (event_flag) # return boolean

# Logic for detecting public bucket via CLI
# Function takes a dictionary as input
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
	# Initializing an empty list to append the dictionary events
	CloudTrail_Events_List = []
	with open('aws_cloudtrail_events.json') as f:
	    for cloudtrailEvent in f: # loop through the JSON object
	        eventDict = json.loads(cloudtrailEvent) # convert JSON object to a dictionary 
	        CloudTrail_Events_List.append(eventDict) # add dictionary to the list

	event_count=0 # initializing event count

	for event in CloudTrail_Events_List: # loop through list of event dictionaries

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