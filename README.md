# internConnect
This repository contains the alexa skills code for InternConnect - a novel and fun way for interns to connect and learn about Amazon during their pre-onboarding period

Directory 'lambda' contains the python code that helps connect the various Alexa skill intents to perform various actions by intern connect.

The following skills are present: 
1) Send a message to be heard by another intern: 
When an intern sends a message , the message is added into the corresponding Dynamo DB table. This message will be picked up by another intern who uses the 'Play a message' 
skill. 
2) Play a message from an intern and possibly connect with them:
When 'Play a message' skill is called, Alexa would pick a message from Dynamo DB to play to the user. If the user is interested in connecting with the sender of the
message, saying 'Connect' will trigger Alexa to send the message and email details of the sender to the user. 
3) Listen to the Amazon Fact of the Day:
This skill randomly picks up facts about Amazon and plays them out for the listener.
4) Learn more about the Amazon Principles: 
The skill plays out an Amazon principle and asks the user if they would like to hear an audio clipping from the Amazon Leadership. 
5) Broadcast information to all interns: 
This feature was added to allow Student programs to reach out to interns via Alexa, providing them any additional details for pre-onboarding.

