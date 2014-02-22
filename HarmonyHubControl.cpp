/******************************************************************************
  Permission is hereby granted, free of charge, to any person obtaining a copy  
  of this software and associated documentation files (the "Software"), to deal 
  in the Software without restriction, including without limitation the rights 
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
  copies of the Software, and to permit persons to whom the Software is 
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all 
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
  SOFTWARE.
*/

#include <algorithm>
#include <string>
#include <map>
#include "csocket.h"

std::string errorString;
std::string resultString;

#define LOGITECH_AUTH_URL "https://svcs.myharmony.com/CompositeSecurityServices/Security.svc/json/GetUserAuthToken"
#define LOGITECH_AUTH_HOSTNAME "svcs.myharmony.com"
#define LOGITECH_AUTH_PATH "/CompositeSecurityServices/Security.svc/json/GetUserAuthToken"
#define HARMONY_COMMUNICATION_PORT 5222
#define CONNECTION_ID "12345678-1234-5678-1234-123456789012-1"

#include <iostream>

static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

char databuffer[1000000];

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';

    }

    return ret;

}

std::string base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}


//  Logs into the Logitech Harmony web service
//  Returns a base64-encoded string containing a 48-byte Login Token in the third parameter
int harmonyWebServiceLogin(std::string strUserEmail, std::string strPassword, std::string& strAuthorizationToken )
{
    if(strUserEmail.length() == 0 || strPassword.length() == 0)
    {
        errorString = "harmonyWebServiceLogin : Empty email or password provided";
        return 1;
    } 


    // Build JSON request
    std::string strJSONText = "{\"email\":\"";
    strJSONText.append(strUserEmail.c_str());
    strJSONText.append("\",\"password\":\"");
    strJSONText.append(strPassword.c_str());
    strJSONText.append("\"}");

    std::string strHttpPayloadText;

    csocket authcsocket;
    authcsocket.connect("svcs.myharmony.com", 80);

    if (authcsocket.getState() != csocket::CONNECTED)
    {
        errorString = "harmonyWebServiceLogin : Unable to connect to Logitech server";
        return 1;
    }

    char contentLength[32];
    sprintf( contentLength, "%d", strJSONText.length() );

    std::string strHttpRequestText;

    strHttpRequestText = "POST ";
    strHttpRequestText.append(LOGITECH_AUTH_URL);
    strHttpRequestText.append(" HTTP/1.1\r\nHost: ");
    strHttpRequestText.append(LOGITECH_AUTH_HOSTNAME);
    strHttpRequestText.append("\r\nAccept-Encoding: identity\r\nContent-Length: ");
    strHttpRequestText.append(contentLength);
    strHttpRequestText.append("\r\ncontent-type: application/json;charset=utf-8\r\n\r\n");

    authcsocket.write(strHttpRequestText.c_str(), strHttpRequestText.size());
    authcsocket.write(strJSONText.c_str(), strJSONText.length());

    memset(databuffer, 0, 1000000);
    authcsocket.read(databuffer, 1000000, false);
    strHttpPayloadText = databuffer;/* <- Expect: 0x00def280 "HTTP/1.1 200 OK Server: nginx/1.2.4 Date: Wed, 05 Feb 2014 17:52:13 GMT Content-Type: application/json; charset=utf-8 Content-Length: 127 Connection: keep-alive Cache-Control: private X-AspNet-Version: 4.0.30319 X-Powered-By: ASP.NET  {"GetUserAuthTokenResult":{"AccountId":0,"UserAuthToken":"KsRE6VVA3xrhtbqFbh0jWn8YTiweDeB\/b94Qeqf3ofWGM79zLSr62XQh8geJxw\/V"}}"*/

    // Parse the login authorization token from the response
    std::string strAuthTokenTag = "UserAuthToken\":\"";
    int pos = (int)strHttpPayloadText.find(strAuthTokenTag);
    if(pos == std::string::npos)
    {
        errorString = "harmonyWebServiceLogin : Logitech web service response does not contain a login authorization token";
        return 1;  
    }

    strAuthorizationToken = strHttpPayloadText.substr(pos + strAuthTokenTag.length());
    pos = (int)strAuthorizationToken.find("\"}}");
    strAuthorizationToken = strAuthorizationToken.substr(0, pos);

    // Remove forward slashes
    strAuthorizationToken.erase(std::remove(strAuthorizationToken.begin(), strAuthorizationToken.end(), '\\'), strAuthorizationToken.end());
    return 0;
}

int connectToHarmony(std::string strHarmonyIPAddress, int harmonyPortNumber, csocket& harmonyCommunicationcsocket)
{
    if(strHarmonyIPAddress.length() == 0 || harmonyPortNumber == 0 || harmonyPortNumber > 65535)
    {
        errorString = "connectToHarmony : Empty Harmony IP Address or Port";
        return 1;
    }

    harmonyCommunicationcsocket.connect(strHarmonyIPAddress.c_str(), harmonyPortNumber);

    if (harmonyCommunicationcsocket.getState() != csocket::CONNECTED)
    {
        errorString = "connectToHarmony : Unable to connect to specified IP Address on specified Port";
        return 1;
    }

    return 0;
}

int startCommunication(csocket* communicationcsocket, std::string strUserName, std::string strPassword)
{
    if(communicationcsocket == NULL || strUserName.length() == 0 || strPassword.length() == 0)
    {
        errorString = "startCommunication : Invalid communication parameter(s) provided";
        return 1;
    } 

    // Start communication
    std::string data = "<stream:stream to='connect.logitech.com' xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xml:lang='en' version='1.0'>";
    communicationcsocket->write(data.c_str(), data.length());
    memset(databuffer, 0, 1000000);
    communicationcsocket->read(databuffer, 1000000, false);
    
    std::string strData = databuffer;/* <- Expect: <?xml version='1.0' encoding='iso-8859-1'?><stream:stream from='' id='XXXXXXXX' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features> */

    data = "<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\" mechanism=\"PLAIN\">";
    std::string tmp = "\0";
    tmp.append(strUserName);
    tmp.append("\0");
    tmp.append(strPassword);
    data.append(base64_encode(tmp.c_str(), tmp.length()));
    data.append("</auth>");
    communicationcsocket->write(data.c_str(), data.length());
    
    memset(databuffer, 0, 1000000);
    communicationcsocket->read(databuffer, 1000000, false);
    
    strData = databuffer; /* <- Expect: <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/> */
    if(strData != "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
    {
        errorString = "startCommunication : connection error";
        return 1;
    } 

    data = "<stream:stream to='connect.logitech.com' xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xml:lang='en' version='1.0'>";
    communicationcsocket->write(data.c_str(), data.length());
    
    memset(databuffer, 0, 1000000);
    communicationcsocket->read(databuffer, 1000000, false);

    strData = databuffer; /* <- Expect: <?xml version='1.0' encoding='iso-8859-1'?><stream:stream from='' id='057a30bd' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features> */

    return 0;
}

int swapAuthorizationToken(csocket* authorizationcsocket, std::string& strAuthorizationToken)
{
    if(authorizationcsocket == NULL || strAuthorizationToken.length() == 0)
    {
        errorString = "swapAuthorizationToken : NULL csocket or empty authorization token provided";
        return 1;
    }

    if(startCommunication(authorizationcsocket, "guest", "gatorade.") != 0)
    {
        errorString = "swapAuthorizationToken : Communication failure";
        return 1;
    }

    std::string strData;
    std::string sendData;
    
    // GENERATE A LOGIN ID REQUEST USING THE HARMONY ID AND LOGIN AUTHORIZATION TOKEN 
    sendData = "<iq type=\"get\" id=\"";
    sendData.append(CONNECTION_ID);
    sendData.append("\"><oa xmlns=\"connect.logitech.com\" mime=\"vnd.logitech.connect/vnd.logitech.pair\">token=");
    sendData.append(strAuthorizationToken.c_str());
    sendData.append(":name=foo#iOS6.0.1#iPhone</oa></iq>");

    std::string strIdentityTokenTag = "identity=";
    int pos = std::string::npos;
    
    authorizationcsocket->write(sendData.c_str(), sendData.length());
    
    memset(databuffer, 0, 1000000);
    authorizationcsocket->read(databuffer, 1000000, false);
        
    strData = databuffer; /* <- Expect: <iq/> ... <success xmlns= ... identity=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:status=succeeded ... */

    if(strData.find("<iq/>") != 0)
    {
         errorString = "swapAuthorizationToken : Invalid Harmony response";
         return 1;  
    }

    bool bIsDataReadable = false;
    authorizationcsocket->canRead(&bIsDataReadable, 1);
    if(!bIsDataReadable && strData == "<iq/>")
    {
        bIsDataReadable = true;
    }

    while(bIsDataReadable)
    {
        memset(databuffer, 0, 1000000);
        authorizationcsocket->read(databuffer, 1000000, false);
        strData.append(databuffer);
        authorizationcsocket->canRead(&bIsDataReadable, 1);
    };

    // Parse the session authorization token from the response
    pos = (int)strData.find(strIdentityTokenTag);
    if(pos == std::string::npos)
    {
        errorString = "swapAuthorizationToken : Logitech Harmony response does not contain a session authorization token";
        return 1;  
    }
    
    strAuthorizationToken = strData.substr(pos + strIdentityTokenTag.length());

    pos = (int)strAuthorizationToken.find(":status=succeeded");
    if(pos == std::string::npos)
    {
        errorString = "swapAuthorizationToken : Logitech Harmony response does not contain a valid session authorization token";
        return 1;  
    }
    strAuthorizationToken = strAuthorizationToken.substr(0, pos);

    return 0;
}


int submitCommand(csocket* commandcsocket, std::string& strAuthorizationToken, std::string strCommand, std::string strCommandParameter, std::string strCommandParameterTwo)
{
    if(commandcsocket== NULL || strAuthorizationToken.length() == 0)
    {
        errorString = "submitCommand : NULL csocket or empty authorization token provided";
        return 1;
    }

    std::string lstrCommand = strCommand;
    if(lstrCommand.length() == 0)
    {
        // No command provided, return query for the current activity
        lstrCommand = "get_current_activity_id";
        return 0;
    }

    std::string strData;

    std::string sendData;
    
    sendData = "<iq type=\"get\" id=\"";
    sendData.append(CONNECTION_ID);
    sendData.append("\"><oa xmlns=\"connect.logitech.com\" mime=\"vnd.logitech.harmony/vnd.logitech.harmony.engine?");

    // Issue the provided command
    if(lstrCommand == "get_current_activity_id")
    {
        sendData.append("getCurrentActivity\" /></iq>");
    }
    if(lstrCommand == "get_config")
    {
        sendData.append("config\"></oa></iq>");        
    }
    else if (lstrCommand == "start_activity")
    {
        sendData.append("startactivity\">activityId=");
        sendData.append(strCommandParameter.c_str());
        sendData.append(":timestamp=0</oa></iq>");
    }
    else if (lstrCommand == "issue_action")
    {
        sendData.append("holdAction\">action={\"type\"::\"IRCommand\",\"deviceId\"::\"");
        sendData.append(strCommandParameter.c_str());
        sendData.append("\",\"command\"::\"");
        sendData.append(strCommandParameterTwo.c_str());
        sendData.append("\"}:status=press</oa></iq>");
    }

    commandcsocket->write(sendData.c_str(), sendData.length());
    
    memset(databuffer, 0, 1000000);
    commandcsocket->read(databuffer, 1000000, false);
    strData = databuffer; /* <- Expect: strData  == <iq/> */
    
    std::string iqTag = "<iq/>";
    int pos = (int)strData.find(iqTag);

    if(pos != 0)
    {
        errorString = "submitCommand: Invalid Harmony response";
        return 1;  
    }

    bool bIsDataReadable = false;
    commandcsocket->canRead(&bIsDataReadable, 1);

    if(bIsDataReadable == false && strData == "<iq/>")
    {
        bIsDataReadable = true;
    }

    if(strCommand != "issue_action")
    {
		while(bIsDataReadable)
		{
			memset(databuffer, 0, 1000000);
			commandcsocket->read(databuffer, 1000000, false);
			strData.append(databuffer);
			commandcsocket->canRead(&bIsDataReadable, 1);
		};
	}
    
    resultString = strData;

    if(strCommand == "get_current_activity_id")
    {
        int resultStartPos = resultString.find("result=");
        int resultEndPos = resultString.find("]]>");
        if(resultStartPos != std::string::npos && resultEndPos != std::string::npos)
        {
            resultString = "Current Activity ID is : " + resultString.substr(resultStartPos + 7, resultEndPos - resultStartPos - 7);
        }
    }
    else if(strCommand == "get_config")
    {
        commandcsocket->canRead(&bIsDataReadable, 1);

        while(bIsDataReadable)
        {
            memset(databuffer, 0, 1000000);
            commandcsocket->read(databuffer, 1000000, false);
            strData.append(databuffer);
            commandcsocket->canRead(&bIsDataReadable, 1);
        };

        pos = strData.find("![CDATA[{");
        if(pos != std::string::npos)
        {
            resultString = "Logitech Harmony Configuration : \n" + strData.substr(pos + 9);
        }
    }
    else if (strCommand == "start_activity" || strCommand == "issue_action")
    {
        resultString = "";
    }
    return 0;
}


int parseConfiguration(std::string strConfiguration, std::map< std::string, std::string>& activitiesMap, std::map< std::string, std::string>& devicesMap)
{
    int suggestedDisplayStartPos = strConfiguration.find("suggestedDisplay");
    while(suggestedDisplayStartPos != std::string::npos)
    {
        int modelStartPos = strConfiguration.find("model\":\"", suggestedDisplayStartPos);
        int labelStartPos = strConfiguration.find("\"label\":\"", suggestedDisplayStartPos);
        if(modelStartPos != std::string::npos && modelStartPos < suggestedDisplayStartPos + 50)
        {
            // We may have a device
            int modelEndPos = strConfiguration.find("\",\"", modelStartPos);
            int manufacturerStartPos = strConfiguration.find("manufacturer\":\"", modelEndPos);
            int manufacturerEndPos = strConfiguration.find("\",\"", manufacturerStartPos);
            if(manufacturerStartPos < modelStartPos+150)
            {
                // we definitely have a device
                std::string strDeviceModel = strConfiguration.substr(modelStartPos+8, modelEndPos-modelStartPos-8);
                std::string strManufacturer = strConfiguration.substr(manufacturerStartPos+15, manufacturerEndPos-manufacturerStartPos-15);
                devicesMap.insert(std::map< std::string, std::string>::value_type(strManufacturer, strDeviceModel));
            }
        }

        if(labelStartPos != std::string::npos && labelStartPos < suggestedDisplayStartPos + 50)
        {
            // We may have an activity
            int idStartPos = strConfiguration.find("\",\"id\":", labelStartPos);
            int activityTypeDNPos = strConfiguration.find("\",\"activityTypeDisplayName\"", idStartPos);
            if(activityTypeDNPos < idStartPos+20)
            {
                // we definitely have an activity
                std::string strActivityLabel = strConfiguration.substr(labelStartPos+9, idStartPos-labelStartPos-9);
                std::string strActivityID = strConfiguration.substr(idStartPos+8, activityTypeDNPos-idStartPos-8);
                activitiesMap.insert(std::map< std::string, std::string>::value_type(strActivityLabel, strActivityID));
            }
        }
        suggestedDisplayStartPos = strConfiguration.find("suggestedDisplay", suggestedDisplayStartPos+16);
    }

    return 0;
}

int main(int argc, char * argv[])
{
    if (argc < 4)
    {
        printf("Syntax:\n");
        printf("HarmonyHubControl.exe [email] [password] [harmony_ip] [command (optional)]\n");
        printf("    where command can be any of the following:\n");
        printf("        list_activities\n");
        printf("        get_current_activity_id\n");
        printf("        start_activity [ID]\n");
        printf("        issue_action [deviceId] [command]\n");
        printf("        list_devices\n");
        printf("        get_config\n");
        printf("\n");
        return 0;
    }

    std::string strUserEmail = argv[1];
    std::string strUserPassword = argv[2];
    std::string strHarmonyIP = argv[3];
	std::string strCommand;
    std::string strCommandParameter;
    std::string strCommandParameterTwo;
    
    int harmonyPortNumber = HARMONY_COMMUNICATION_PORT;

    // User requested an action to be performed
    if(argc >= 5)
    {
        strCommand = argv[4];
    }
    if(argc>=6)
    {
        strCommandParameter = argv[5];
    }

    if(argc==7)
    {
        strCommandParameterTwo = argv[6];
    }

    //QNetworkProxyFactory::setUseSystemConfiguration(true);

    printf("LOGITECH WEB SERVICE LOGIN     : ");

    // Log into the logitech web service to retrieve the login authorization token
    std::string strAuthorizationToken;
    if(harmonyWebServiceLogin(strUserEmail, strUserPassword, strAuthorizationToken) == 1)
    {
        printf("FAILURE\n");
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }
    printf("SUCCESS\n");

    //printf("\nLogin Authorization Token is: %s\n\n", strAuthorizationToken.c_str());


    // Log into the harmony hub to convert the login authorization token for a 
    // session authorization token
    printf("HARMONY COMMUNICATION LOGIN    : ");

    csocket authorizationcsocket;
    if(connectToHarmony(strHarmonyIP, harmonyPortNumber, authorizationcsocket) == 1)
    {
        printf("FAILURE\n");
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }

    if(swapAuthorizationToken(&authorizationcsocket, strAuthorizationToken) == 1)
    {
        printf("FAILURE\n");
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }

    printf("SUCCESS\n");
    
    //printf("\nSession Authorization Token is: %s\n\n", strAuthorizationToken.c_str());

    // We've successfully obtained our session authorization token from the harmony hub 
    // using the login authorization token we received earlier from the Logitech web service.
    // Now, disconnect from the harmony and reconnect using the mangled session token 
    // as our username and password to issue a command.

    printf("HARMONY COMMAND SUBMISSION     : ");

    csocket commandcsocket;
    if(connectToHarmony(strHarmonyIP, harmonyPortNumber, commandcsocket) == 1)
    {
        printf("FAILURE\n");
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }

    std::string strUserName = strAuthorizationToken;
    //strUserName.append("@connect.logitech.com/gatorade.");
    std::string strPassword = strAuthorizationToken;
    
    if(startCommunication(&commandcsocket, strUserName, strPassword) == 1)
    {
        errorString = "Communication failure";
        return 1;
    }

    std::string lstrCommand = strCommand;

    if(strCommand == "list_activities" || strCommand == "list_devices")
    {
        lstrCommand = "get_config";
    }

    if(submitCommand(&commandcsocket, strAuthorizationToken, lstrCommand, strCommandParameter, strCommandParameterTwo) == 1)
    {
        printf("FAILURE\n");
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }

    printf("SUCCESS\n");


    if(lstrCommand == "get_config")
    {
        printf("PARSE ACTIVITIES AND DEVICES   : ");
        
        std::map< std::string, std::string> activitiesMap;
        std::map< std::string, std::string> devicesMap;
        if(parseConfiguration(resultString, activitiesMap, devicesMap) == 1)
        {
            printf("FAILURE\n");
            printf("ERROR : %s\n", errorString.c_str());
            return 1;
        }

        if(strCommand == "list_activities")
        {
            resultString = "Activities Available via Harmony : \n\n";
            std::map< std::string, std::string>::iterator it = activitiesMap.begin();
            std::map< std::string, std::string>::iterator ite = activitiesMap.end();
            for(; it != ite; ++it)
            {
                resultString.append(it->first);
                resultString.append(" - ");
                resultString.append(it->second);
                resultString.append("\n");

            }
        }

        if(strCommand == "list_devices")
        {
            resultString = "Devices Controllable via Harmony : \n\n";
            std::map< std::string, std::string>::iterator it = devicesMap.begin();
            std::map< std::string, std::string>::iterator ite = devicesMap.end();
            for(; it != ite; ++it)
            {
                resultString.append(it->first);
                resultString.append(" - ");
                resultString.append(it->second);
                resultString.append("\n");
                
            }
        }

        printf("SUCCESS\n\n");
    }

    printf("%s\n\n", resultString.c_str());

    return 0;
}

