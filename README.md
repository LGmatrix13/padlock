# Dev Setup

## Install Dependencies

First install the necessary dependencies with `pip install -r requirements.txt`

## Run Locally

Run the flask server locally in VS Code by using the "Run and Debug" tool (Ctrl + Shift +D). Select python flask server. VS Code should start running the server at `localhost:5000`

# Account Setup

## Create Contacts/Accounts

The server should prompt you to provide a name to generate your keypair. Fill the form
to be redirect to downlodad your contact. Run the server on your browser's guest/incognito mode to create another account/contact to test with.

## Download and Exchange

Download each contact. After downloading each contact, upload them to the other contact by clicking "Add Contact" in the navigation.

## Send a Message

Go to "Send Location." Select the appropiate contact in the dropdown. Also accept location
permissions to automatically populate the lat/long fields. Add a note and hit submit.

## View Messages

Go to "Locations." You should see a verified message badge, the user's name, and the note. Clicking on the card should open the lat/long coordinates in Google Maps.

## Clearing Data

All data is stored in the server's memory. As such, it is ephemeral. Simply reset the server to clear all the data. Note: users will have to re-create contacts and exchange them again if this happens.
