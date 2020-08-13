# -*- coding: utf-8 -*-

# This sample demonstrates handling intents from an Alexa skill using the Alexa Skills Kit SDK for Python.
# Please visit https://alexa.design/cookbook for additional examples on implementing slots, dialog management,
# session persistence, api calls, and more.
# This sample is built using the handler classes approach in skill builder.
import logging
import prompts
import json
import boto3
import random
import smtplib
import requests
from ask_sdk_core.skill_builder import CustomSkillBuilder
from ask_sdk_core.api_client import DefaultApiClient
from ask_sdk_model.ui import AskForPermissionsConsentCard

from random import randint

import ask_sdk_core.utils as ask_utils

from ask_sdk_core.skill_builder import SkillBuilder
from ask_sdk_core.dispatch_components import (
    AbstractRequestHandler, AbstractExceptionHandler,
    AbstractRequestInterceptor, AbstractResponseInterceptor)
from ask_sdk_core.handler_input import HandlerInput

import uuid
from ask_sdk_model import Response

from ask_sdk_model.dialog import (
    ElicitSlotDirective, DelegateDirective)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

NOTIFY_MISSING_PERMISSIONS = ("Please enable Contact informations permissions in "
                              "the Amazon Alexa app.")

def get_dynamodb_table():
    sts_client = boto3.client('sts')
    assumed_role_object=sts_client.assume_role(RoleArn="arn:aws:iam::347887713760:role/AlexaSkillDynamoRole2", RoleSessionName="AssumeRoleSession1")
    credentials=assumed_role_object['Credentials']
    dynamodb = boto3.resource('dynamodb', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    return dynamodb.Table('AlexaTable')


dynamodb_table = get_dynamodb_table()
randomMessage = []
permissions = ["alexa::profile:email:read", "alexa::profile:name:read"]

def get_data():
    try:
        response = dynamodb_table.scan()
        responseValues = response['Items'] #Items contain the actual json object
        internMessages = []
        for value in responseValues:
            if 'is_broadcast' in value and value['is_broadcast'] is False:
                internMessages.append(value)
        maxLen = len(internMessages)-1
        logger.info(internMessages)
        randomMessageIndex = randint(0, maxLen)
        return internMessages[randomMessageIndex]
    except ResourceNotExistsError:
        # Exception handling
        return "Oh no! There arent any messages for you."
    except Exception as e:
        # Exception handling
        return "Oh no! There arent any messages for you."



def get_broadcast_messages(user_email):
    try:
        response = dynamodb_table.scan()
        responseValues = response['Items']
        response = []
        for value in responseValues:
            if 'is_broadcast' in value and value['is_broadcast'] is True: 
                if user_email not in value['users_viewed']:
                    response.append(value)
        return response
        
    except ResourceNotExistsError:
        logger.error("ResourceNotExistsError")
        raise
    except Exception as e:
        # Exception handling
        logger.error(e)
        raise e

def put_data(email, message):
    try:
        resp = dynamodb_table.put_item(Item={
               "id": str(uuid.uuid4()),
                "email": email,
                "message":message
            },
                ConditionExpression='attribute_not_exists(id)'
            )
    except dynamodb_client.exceptions.ConditionalCheckFailedException:
        return "Client error. Resource exists"
    return resp 

def put_data(email, message, is_broadcast, users_viewed):
    try:
        resp = dynamodb_table.put_item(Item={
               "id": str(uuid.uuid4()),
                "email": email,
                "message":message,
                "is_broadcast" : is_broadcast,
                "users_viewed": users_viewed
            },
                ConditionExpression='attribute_not_exists(id)'
            )
    except dynamodb_client.exceptions.ConditionalCheckFailedException:
        return "Client error. Resource exists"
    return resp


def update_data(id, users_viewed):
    try:
        resp = dynamodb_table.update_item(Key={
            'id': id,
        },
        UpdateExpression="set users_viewed=:r",
        ExpressionAttributeValues={
            ':r': users_viewed,
        },
        # ReturnValues="UPDATED_NEW"
        )
    except dynamodb_client.exceptions.ConditionalCheckFailedException:
        return "Client error. Resource exists"
    return resp 

def get_user_info(session):
    logger.info(session)
    access_token = session.api_access_token
    amazonProfileURL = session.api_endpoint + "/v2/accounts/~current/settings/Profile.email"
    headers = {
        'authorization': "Bearer " + access_token,
        'content-type': "application/json"
    }
    r = requests.get(url=amazonProfileURL, headers=headers)
    logger.info(r.json())
    if r.status_code == 200:
        return r.json()
    else:
        return False

class LaunchRequestHandler(AbstractRequestHandler):
    """Handler for Skill Launch."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool

        return ask_utils.is_request_type("LaunchRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "Welcome to Intern Connect! You can do the following - 1) Send a message to an intern. 2) Play a message from an intern. 3) Listen to the Amazon Fact of the Day. 4) Listen to Amazon's Leadership Principles. 5) Broadcast a message. What would you like to do ?"
        
        user_preferences_client = handler_input.service_client_factory.get_ups_service()
        # Fetch User Email From Alexa Customer Settings API
        user_email = user_preferences_client.get_profile_email()
        
        broadcast_messages = get_broadcast_messages(user_email)
        if broadcast_messages and len(broadcast_messages) > 0:
            speak_output += " While you decide, here are some messages that were broadcasted to all interns - "
            start = 1
            for message in broadcast_messages:
                speak_output += (str(start) + ") " + message['message'] + ". ")
                start += 1
                message['users_viewed'] += user_email
                update_data(message['id'], message['users_viewed'])
        
        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )

class HelpIntentHandler(AbstractRequestHandler):
    """Handler for Help Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.HelpIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "You can say hello to me! How can I help?"

        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )


class CancelOrStopIntentHandler(AbstractRequestHandler):
    """Single handler for Cancel and Stop Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return (ask_utils.is_intent_name("AMAZON.CancelIntent")(handler_input) or
                ask_utils.is_intent_name("AMAZON.StopIntent")(handler_input))

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "Goodbye!"

        return (
            handler_input.response_builder
                .speak(speak_output)
                .response
        )

class YesOrNoIntentHandler(AbstractRequestHandler):
    """Single handler for Yes and No Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        logger.info(handler_input)
        return (ask_utils.is_intent_name("YesIntent")(handler_input) or
                ask_utils.is_intent_name("NoIntent")(handler_input))

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        session_attr = handler_input.attributes_manager.session_attributes
        logger.info(session_attr)
        
        if("leadershipIntent" in session_attr.keys()
            and session_attr["leadershipIntent"]==True
            and ask_utils.is_intent_name("YesIntent")(handler_input)):
            speak_output = '<audio src="https://tempvalidationbucket.s3-us-west-2.amazonaws.com/Customer_Obsession_-_Customer_vs._Competitor+(2).mp3" />'
        else:
            speak_output = "Goodbye!"

        return (
            handler_input.response_builder
                .speak(speak_output)
                .response
        )


class SessionEndedRequestHandler(AbstractRequestHandler):
    """Handler for Session End."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("SessionEndedRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        reason = handler_input.request_envelope.request.reason
        logger.info(type(reason))
        # Any cleanup logic goes here.
        if reason == "EXCEEDED_MAX_REPROMPTS":
            speak_output = "Oops looks like you have exceeded the number of retries. Why don't we start again?"
        else:
            speak_output = "Your session seems to have ended. Try saying - Intern Jam, to start again."
        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )

class CatchAllExceptionHandler(AbstractExceptionHandler):
    """Generic error handling to capture any syntax or routing errors. If you receive an error
    stating the request handler chain is not found, you have not implemented a handler for
    the intent being invoked or included it in the skill builder below.
    """
    def can_handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> bool
        return True

    def handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> Response
        logger.error(exception, exc_info=True)

        speak_output = "Sorry, I had trouble doing what you asked. Please try again."

        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )



class FactOfTheDayIntentHandler(AbstractRequestHandler):
    """Handler for FactOfTheDayIntent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return (ask_utils.is_intent_name("FactOfTheDayIntent")(handler_input))

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        # speak_output = "Sure! I would love to tell you a fact. Did you know about the Low Flying Hawk Building?"

        data = handler_input.attributes_manager.request_attributes["_"]
        logger.info(data[prompts.FACTS])

        random_fact = random.choice(data[prompts.FACTS])
        logger.info("fact selected:- {}".format(random_fact))
        speak_output = data[prompts.GET_FACT_MESSAGE].format(random_fact)

        return (handler_input.response_builder
                     .speak(speak_output)
                     .set_should_end_session(False)
                     .response)



class LeadershipIntentHandler(AbstractRequestHandler):
    """Handler for LeadershipPrincipleIntent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return (ask_utils.is_intent_name("LeadershipPrincipleIntent")(handler_input))

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        logger.info("--------------------")
        data = handler_input.attributes_manager.request_attributes["_"]

        potd_dict = random.choice(data[prompts.PRINCIPLES])
        potd = potd_dict[prompts.PRINCIPLE]
        leader = potd_dict[prompts.LEADER]
        logger.info("leadership principal:- {}, leader:- {}".format(potd, leader))
        speak_output = potd_dict[prompts.MESSAGE].format(potd, leader)
        session_attr = handler_input.attributes_manager.session_attributes
        session_attr["leadershipIntent"] = True


        return (handler_input.response_builder
                     .speak(speak_output)
                     .set_should_end_session(False)
                     .response)


class Interceptor(AbstractRequestInterceptor):
    """
    Add function to request attributes in amazon_facts.json file.
    """

    def process(self, handler_input):
        
        if(ask_utils.is_intent_name("FactOfTheDayIntent")(handler_input)):
            with open("amazon_facts.json") as amz_prompts:
                data = json.load(amz_prompts)
                
            logger.info("Inside the interceptor")
            handler_input.attributes_manager.request_attributes["_"] = data
            logger.info("Interceptor: {}".format(data[prompts.FACTS]))
            
        elif(ask_utils.is_intent_name("LeadershipPrincipleIntent")(handler_input)):
            with open("leadership_principles.json") as amz_prompts:
                data = json.load(amz_prompts)
            
            logger.info("Inside the principles interceptor")
            handler_input.attributes_manager.request_attributes["_"] = data
            logger.info("Interceptor: {}".format(data[prompts.PRINCIPLES]))


class SendAMessageIntentHandler(AbstractRequestHandler):
    """Handler for SendAMessageIntent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("SendAMessageIntent")(handler_input) 

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        
        messageSlot = ask_utils.request_util.get_slot(handler_input, "message")
        req_envelope = handler_input.request_envelope
        response_builder = handler_input.response_builder
        service_client_fact = handler_input.service_client_factory

        # Check if you have the permissions
        if not (req_envelope.context.system.user.permissions and
                req_envelope.context.system.user.permissions.consent_token):
            response_builder.speak(NOTIFY_MISSING_PERMISSIONS)
            response_builder.set_card(
                AskForPermissionsConsentCard(permissions=permissions))
            return response_builder.response
        
        device_id = req_envelope.context.system.device.device_id
        user_preferences_client = handler_input.service_client_factory.get_ups_service()
        # Fetch User Email From Alexa Customer Settings API
        user_email = user_preferences_client.get_profile_email()
        # Go to town with the email
        print ("USER EMAIL::", user_email) # String of the user e-mail

        #slots = handler_input.request_envelope.request.intent.slots
        #messageSlot = slots.get('message', None)
        #if messageSlot.confirmation_status === "DENIED": 
        #    speak_output = "Sure! Your message will not be sent."
        #else: 
        
        upsService = handler_input.service_client_factory.get_ups_service()
        logger.info(upsService.get_profile_email())
        logger.info(upsService.get_profile_name())
        
        #user = get_user_info(handler_input.request_envelope.context.system)
        if messageSlot.value:
            speak_output = "Cool! I will send your message to an intern. You can now sit back and relax!"
            message = messageSlot.value
            put_data(user_email, message, False, "")
        
        return (
            handler_input.response_builder
                .speak(speak_output)
                .set_should_end_session(True)
                .response
        )


class ReceiveAMessageIntentHandler(AbstractRequestHandler):
    """Handler for ReceiveAMessageIntent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("ReceiveAMessageIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        req_envelope = handler_input.request_envelope
        response_builder = handler_input.response_builder
        service_client_fact = handler_input.service_client_factory

        # Check if you have the permissions
        if not (req_envelope.context.system.user.permissions and
                req_envelope.context.system.user.permissions.consent_token):
            response_builder.speak(NOTIFY_MISSING_PERMISSIONS)
            response_builder.set_card(
                AskForPermissionsConsentCard(permissions=permissions))
            return response_builder.response
        
        device_id = req_envelope.context.system.device.device_id
        user_preferences_client = handler_input.service_client_factory.get_ups_service()
        # Fetch User Email From Alexa Customer Settings API
        user_email = user_preferences_client.get_profile_email()
        # Go to town with the email
        print ("USER EMAIL::", user_email) # String of the user e-mail
        
        confimrationSlot = ask_utils.request_util.get_slot(handler_input, "confirmation")
        global randomMessage
        if confimrationSlot.value is None:
            speak_output = "Sure! Playing a message for you."
            randomMessage = get_data()
            try: 
                logger.info(randomMessage)
                logger.info(randomMessage['message'])
                speak_output = speak_output + '<amazon:emotion name="excited" intensity="medium">' + randomMessage['message'] + '</amazon:emotion><break time="2s"/>' + "\nSay 'Connect' if you would like me to email this message to you? "
            except Exception as e:
                speak_output = "Oh no! There arent any messages for you."
            return (
                handler_input.response_builder
                    .speak(speak_output)
                    .add_directive(
                        ElicitSlotDirective(slot_to_elicit='confirmation')
                        )
                    .response
            )
        elif confimrationSlot.value.lower() == 'connect':
            try:
                logger.info(randomMessage)
                server = smtplib.SMTP("smtp.gmail.com", 587)
                server.ehlo()
                server.starttls()
                server.ehlo()           
                server.login('internconnectalexaskill', 'lellel123')
                message ="\r\n".join([
                          "From: InternConnect <internconnectalexaskill@gmail.com>",
                          "To: " + user_email,
                          "Subject: Message from InternConnect",
                          "",
                          "You have received a message from " + randomMessage['email'] + ": \n"+ randomMessage['message']
                          ]) 
                server.sendmail('internconnectalexaskill@gmail.com', [user_email], message)      
                server.close()
                speak_output = "Sure! I have sent the email. You will receive it in a while."
            except SMTPException:
                logger.error("Error: unable to send email")
                speak_output = "Oops! Something went wrong. I was not able to send you the email."
            
            return (
                handler_input.response_builder
                    .speak(speak_output)
                    .set_should_end_session(True)
                    .response
            )
        else:    
            speak_output = "You did not say 'Connect'. I will not email the message."
            
            return (
                handler_input.response_builder
                    .speak(speak_output)
                    .set_should_end_session(True)
                    .response
            )


class BroadcastAMessageIntentHandler(AbstractRequestHandler):
    """Handler for BroadcastAMessageIntent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("BroadcastAMessage")(handler_input)

    def handle(self, handler_input):
        messageSlot = ask_utils.request_util.get_slot(handler_input, "message")
        logger.info(messageSlot)
        
        speak_output = "Cool! I'll broadcast your message to all interns. They'll see the message when they start an intern connect session."
        message = messageSlot.value
        put_data("anelliat@andrew.cmu.edu", message, True, "")
            
        return (
            handler_input.response_builder
                .speak(speak_output)
                .set_should_end_session(True)
                .response
        )



class IntentReflectorHandler(AbstractRequestHandler):
    """The intent reflector is used for interaction model testing and debugging.
    It will simply repeat the intent the user said. You can create custom handlers
    for your intents by defining them above, then also adding them to the request
    handler chain below.
    """
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("IntentRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        intent_name = ask_utils.get_intent_name(handler_input)
        speak_output = "You just triggered " + intent_name + "."

        return (
            handler_input.response_builder
                .speak(speak_output)
                # .ask("add a reprompt if you want to keep the session open for the user to respond")
                .response
        )

# Request and Response loggers
class RequestLogger(AbstractRequestInterceptor):
    """Log the alexa requests."""

    def process(self, handler_input):
        # type: (HandlerInput) -> None
        logger.info("Alexa Request: {}".format(
            handler_input.request_envelope.request))


class ResponseLogger(AbstractResponseInterceptor):
    """Log the alexa responses."""

    def process(self, handler_input, response):
        # type: (HandlerInput, Response) -> None
        logger.info("Alexa Response: {}".format(response))


# The SkillBuilder object acts as the entry point for your skill, routing all request and response
# payloads to the handlers above. Make sure any new handlers or interceptors you've
# defined are included below. The order matters - they're processed top to bottom.


sb = CustomSkillBuilder(api_client=DefaultApiClient())

sb.add_request_handler(LaunchRequestHandler())
sb.add_request_handler(FactOfTheDayIntentHandler())
sb.add_request_handler(LeadershipIntentHandler())
sb.add_request_handler(SendAMessageIntentHandler())
sb.add_request_handler(ReceiveAMessageIntentHandler())
sb.add_request_handler(BroadcastAMessageIntentHandler())
sb.add_request_handler(YesOrNoIntentHandler())

sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(CancelOrStopIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())
sb.add_request_handler(IntentReflectorHandler()) # make sure IntentReflectorHandler is last so it doesn't override your custom intent handlers

sb.add_exception_handler(CatchAllExceptionHandler())

sb.add_global_request_interceptor(Interceptor())
sb.add_global_request_interceptor(RequestLogger())
sb.add_global_response_interceptor(ResponseLogger())

lambda_handler = sb.lambda_handler()