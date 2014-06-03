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
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include "csocket.h"

std::string errorString;
std::string resultString;

#define LOGITECH_AUTH_URL "https://svcs.myharmony.com/CompositeSecurityServices/Security.svc/json/GetUserAuthToken"
#define LOGITECH_AUTH_HOSTNAME "svcs.myharmony.com"
#define LOGITECH_AUTH_PATH "/CompositeSecurityServices/Security.svc/json/GetUserAuthToken"
#define HARMONY_COMMUNICATION_PORT 5222
#define HARMONY_HUB_AUTHORIZATION_TOKEN_FILENAME "HarmonyHub.AuthorizationToken"
#define CONNECTION_ID "12345678-1234-5678-1234-123456789012-1"

#ifdef WIN32
#define sprintf sprintf_s
#endif

void log(const char* message, bool bQuiet)
{
    if(bQuiet)
    {
        return;
    }

    printf("%s\n", message);
}

class Action
{
public:
    std::string m_strCommand;
    std::string m_strName;
    std::string m_strLabel;
    std::string toString()
    {
        return m_strCommand;
    }
};


class Function
{
public:
    std::string m_strName;
    std::vector< Action > m_vecActions;
    std::string toString()
    {
        std::string ret = "    Function: ";
        ret.append(m_strName);
        ret.append("\n      Commands:");
        std::vector<Action>::iterator it = m_vecActions.begin();
        std::vector<Action>::iterator ite = m_vecActions.end();
        for(; it != ite; ++it)
        {
            ret.append("\n\t");
            ret.append(it->toString());
        }
        ret.append("\n");
        return ret;
    }
};

class Device
{
public:
    std::string m_strID;
    std::string m_strLabel;
    std::string m_strManufacturer;
    std::string m_strModel;
    std::string m_strType;
    std::vector< Function > m_vecFunctions;

    std::string toString()
    {
        std::string ret = m_strType;
        ret.append(": ");
        ret.append(m_strLabel);
        ret.append(" (ID = ");
        ret.append(m_strID);
        ret.append(")\n");
        ret.append(m_strManufacturer);
        ret.append(" - ");
        ret.append(m_strModel);
        ret.append("\nFunctions: \n");
        std::vector<Function>::iterator it = m_vecFunctions.begin();
        std::vector<Function>::iterator ite = m_vecFunctions.end();
        for(; it != ite; ++it)
        {
            ret.append(it->toString());
        }
        return ret;
    }
};

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
    authorizationcsocket->canRead(&bIsDataReadable, 0.3f);
    if(!bIsDataReadable && strData == "<iq/>")
    {
        bIsDataReadable = true;
    }

    while(bIsDataReadable)
    {
        memset(databuffer, 0, 1000000);
        authorizationcsocket->read(databuffer, 1000000, false);
        strData.append(databuffer);
        authorizationcsocket->canRead(&bIsDataReadable, 0.3f);
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


int submitCommand(csocket* commandcsocket, std::string& strAuthorizationToken, std::string strCommand, std::string strCommandParameterPrimary, std::string strCommandParameterSecondary)
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
    if(lstrCommand == "get_current_activity_id" || lstrCommand == "get_current_activity_id_raw")
    {
        sendData.append("getCurrentActivity\" /></iq>");
    }
    if(lstrCommand == "get_config_raw")
    {
        sendData.append("config\"></oa></iq>");        
    }
    else if (lstrCommand == "start_activity")
    {
        sendData.append("startactivity\">activityId=");
        sendData.append(strCommandParameterPrimary.c_str());
        sendData.append(":timestamp=0</oa></iq>");
    }
    else if (lstrCommand == "issue_device_command")
    {
        sendData.append("holdAction\">action={\"type\"::\"IRCommand\",\"deviceId\"::\"");
        sendData.append(strCommandParameterPrimary.c_str());
        sendData.append("\",\"command\"::\"");
        sendData.append(strCommandParameterSecondary.c_str());
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
    commandcsocket->canRead(&bIsDataReadable, 0.6f);

    if(bIsDataReadable == false && strData == "<iq/>")
    {
        bIsDataReadable = true;
    }

    if(strCommand != "issue_device_command")
    {
        while(bIsDataReadable)
        {
            memset(databuffer, 0, 1000000);
            commandcsocket->read(databuffer, 1000000, false);
            strData.append(databuffer);
            commandcsocket->canRead(&bIsDataReadable, 0.3f);
        }
    }
    
    resultString = strData;

    if(strCommand == "get_current_activity_id" || strCommand == "get_current_activity_id_raw")
    {
        int resultStartPos = resultString.find("result=");
        int resultEndPos = resultString.find("]]>");
        if(resultStartPos != std::string::npos && resultEndPos != std::string::npos)
        {
            resultString = resultString.substr(resultStartPos + 7, resultEndPos - resultStartPos - 7);
            if(strCommand == "get_current_activity_id")
            {
                resultString.insert(0, "Current Activity ID is : ");
            }
        }
    }
    else if(strCommand == "get_config" || strCommand == "get_config_raw")
    {
        commandcsocket->canRead(&bIsDataReadable, 0.3f);

#ifndef WIN32
        bIsDataReadable = true;
#endif

        while(bIsDataReadable)
        {
            memset(databuffer, 0, 1000000);
            commandcsocket->read(databuffer, 1000000, false);
            strData.append(databuffer);
            commandcsocket->canRead(&bIsDataReadable, 0.3f);
        }
        

        pos = strData.find("![CDATA[{");
        if(pos != std::string::npos)
        {
            resultString = "Logitech Harmony Configuration : \n" + strData.substr(pos + 9);
        }
    }
    else if (strCommand == "start_activity" || strCommand == "issue_device_command")
    {
        resultString = "";
    }
    return 0;
}

int parseAction(const std::string& strAction, std::vector<Action>& vecDeviceActions, const std::string& strDeviceID)
{
    Action a;
    const std::string commandTag = "\\\"command\\\":\\\"";
    int commandStart = strAction.find(commandTag);
    int commandEnd = strAction.find("\\\",\\\"", commandStart);
    a.m_strCommand = strAction.substr(commandStart + commandTag.length(), commandEnd - commandStart - commandTag.length());
    
    const std::string deviceIdTag = "\\\"deviceId\\\":\\\"";
    int deviceIDStart = strAction.find(deviceIdTag, commandEnd);

    const std::string nameTag = "\\\"}\",\"name\":\"";
    int deviceIDEnd = strAction.find(nameTag, deviceIDStart);

    std::string commandDeviceID = strAction.substr(deviceIDStart + deviceIdTag.length(), deviceIDEnd - deviceIDStart - deviceIdTag.length());
    if(commandDeviceID != strDeviceID)
    {
        return 1;
    }

    int nameStart = deviceIDEnd + nameTag.length();

    const std::string labelTag = "\",\"label\":\"";
    int nameEnd = strAction.find(labelTag, nameStart);

    a.m_strName = strAction.substr(nameStart, nameEnd - nameStart);

    int labelStart = nameEnd + labelTag.length();
    int labelEnd = strAction.find("\"}", labelStart);

    a.m_strLabel = strAction.substr(labelStart, labelEnd - labelStart);

    vecDeviceActions.push_back(a);
    return 0;
}

int parseFunction(const std::string& strFunction, std::vector<Function>& vecDeviceFunctions, const std::string& strDeviceID)
{
    Function f;
    int functionNameEnd = strFunction.find("\",\"function\":[{");
    if(functionNameEnd == std::string::npos)
    {
        return 1;
    }
    
    f.m_strName = strFunction.substr(0, functionNameEnd);

    const std::string actionTag = "\"action\":\"";
    int actionStart = strFunction.find(actionTag, functionNameEnd);
    
    while(actionStart != std::string::npos)
    {
        const std::string labelTag = "\"label\":\"";
        int actionEnd = strFunction.find(labelTag, actionStart);
        if(actionEnd == std::string::npos)
        {
            return 1;
        }
        actionEnd = strFunction.find("\"}", actionEnd + labelTag.length());

        std::string strAction = strFunction.substr(actionStart + actionTag.length(), actionEnd - actionStart - actionTag.length());
        parseAction(strAction, f.m_vecActions, strDeviceID);
        
        actionStart = strFunction.find(actionTag, actionEnd);
    }

    vecDeviceFunctions.push_back(f);

    return 0;
}

int parseControlGroup(const std::string& strControlGroup, std::vector<Function>& vecDeviceFunctions, const std::string& strDeviceID)
{
    const std::string nameTag = "{\"name\":\"";
    int funcStartPos = strControlGroup.find(nameTag);
    int funcEndPos = strControlGroup.find("]}");
    while(funcStartPos != std::string::npos)
    {
        std::string strFunction = strControlGroup.substr(funcStartPos + nameTag.length(), funcEndPos - funcStartPos - nameTag.length());
        if(parseFunction(strFunction, vecDeviceFunctions, strDeviceID) != 0)
        {
            return 1;
        }
        funcStartPos = strControlGroup.find(nameTag, funcEndPos);
        funcEndPos = strControlGroup.find("}]}", funcStartPos);
    }

    return 0;
}

int parseConfiguration(const std::string& strConfiguration, std::map< std::string, std::string >& mapActivities, std::vector< Device >& vecDevices)
{
    std::string activityTypeDisplayNameTag = "\",\"activityTypeDisplayName\":\"";
    int activityTypeDisplayNameStartPos = strConfiguration.find(activityTypeDisplayNameTag);
    while(activityTypeDisplayNameStartPos != std::string::npos)
    {
        int activityStart = strConfiguration.rfind("{", activityTypeDisplayNameStartPos);
        if(activityStart != std::string::npos )
        {
            std::string activityString = strConfiguration.substr(activityStart+1, activityTypeDisplayNameStartPos - activityStart-1);
            
            std::string labelTag = "\"label\":\"";
            std::string idTag = "\",\"id\":\"";
            int labelStartPos = activityString.find(labelTag);
            int idStartPos = activityString.find(idTag, labelStartPos);
                        
            // Try to pick up the label
            std::string strActivityLabel = activityString.substr(labelStartPos+9, idStartPos-labelStartPos-9);
            idStartPos += idTag.length();

            // Try to pick up the ID
            std::string strActivityID = activityString.substr(idStartPos, activityString.length() - idStartPos);

            mapActivities.insert(std::map< std::string, std::string>::value_type(strActivityID, strActivityLabel));
        }
        activityTypeDisplayNameStartPos = strConfiguration.find(activityTypeDisplayNameTag, activityTypeDisplayNameStartPos+activityTypeDisplayNameTag.length());
    }

    // Search for devices and commands
    std::string deviceDisplayNameTag = "deviceTypeDisplayName";
    int deviceTypeDisplayNamePos = strConfiguration.find(deviceDisplayNameTag);
    while(deviceTypeDisplayNamePos != std::string::npos && deviceTypeDisplayNamePos != strConfiguration.length())
    {
        //std::string deviceString = strConfiguration.substr(deviceTypeDisplayNamePos);
        int nextDeviceTypeDisplayNamePos = strConfiguration.find(deviceDisplayNameTag, deviceTypeDisplayNamePos + deviceDisplayNameTag.length());

        if(nextDeviceTypeDisplayNamePos == std::string::npos)
        {
            nextDeviceTypeDisplayNamePos = strConfiguration.length();
        }

        Device d;

        // Search for commands
        const std::string controlGroupTag = ",\"controlGroup\":[";
        const std::string controlPortTag = "],\"ControlPort\":";
        int controlGroupStartPos = strConfiguration.find(controlGroupTag, deviceTypeDisplayNamePos);
        int controlGroupEndPos = strConfiguration.find(controlPortTag, controlGroupStartPos + controlGroupTag.length());
        int deviceStartPos = strConfiguration.rfind("{", deviceTypeDisplayNamePos);
        int deviceEndPos = strConfiguration.find("}", controlGroupEndPos);

        if(deviceStartPos != std::string::npos && deviceEndPos != std::string::npos)
        {
            // Try to pick up the ID
            const std::string idTag = "\",\"id\":\"";
            int idStartPos = strConfiguration.find(idTag, deviceStartPos);
            if(idStartPos != std::string::npos && idStartPos < deviceEndPos)
            {
                int idEndPos = strConfiguration.find("\",\"", idStartPos + idTag.length());
                d.m_strID = strConfiguration.substr(idStartPos+idTag.length(), idEndPos-idStartPos-idTag.length());
            }
            else
            {
                deviceTypeDisplayNamePos = nextDeviceTypeDisplayNamePos ;
                continue;
            }

            // Definitely have a device

            // Try to pick up the label
            const std::string labelTag = "\"label\":\"";
            int labelStartPos = strConfiguration.find(labelTag, deviceStartPos);
            if(labelStartPos != std::string::npos && labelStartPos < deviceEndPos)
            {
                int labelEndPos = strConfiguration.find("\",\"", labelStartPos + labelTag.length());
                d.m_strLabel = strConfiguration.substr(labelStartPos + labelTag.length(), labelEndPos-labelStartPos - labelTag.length());
            }

            // Try to pick up the type
            std::string typeTag = ",\"type\":\"";
            int typeStartPos = strConfiguration.find(typeTag, deviceStartPos);
            if(typeStartPos != std::string::npos && typeStartPos < deviceEndPos)
            {
                int typeEndPos = strConfiguration.find("\",\"", typeStartPos + typeTag.length());
                d.m_strType = strConfiguration.substr(typeStartPos + typeTag.length(), typeEndPos - typeStartPos - typeTag.length());
            }

            // Try to pick up the manufacturer
            std::string manufacturerTag = "manufacturer\":\"";
            int manufacturerStartPos = strConfiguration.find(manufacturerTag, deviceStartPos);
            if(manufacturerStartPos != std::string::npos && manufacturerStartPos < deviceEndPos)
            {
                int manufacturerEndPos = strConfiguration.find("\",\"", manufacturerStartPos + manufacturerTag.length());
                d.m_strManufacturer = strConfiguration.substr(manufacturerStartPos+15, manufacturerEndPos-manufacturerStartPos-manufacturerTag.length());
            }

            // Try to pick up the model
            std::string modelTag = "model\":\"";
            int modelStartPos = strConfiguration.find(modelTag, deviceStartPos);
            if(modelStartPos != std::string::npos && modelStartPos < deviceEndPos)
            {
                int modelEndPos = strConfiguration.find("\",\"", modelStartPos + modelTag.length());
                d.m_strModel = strConfiguration.substr(modelStartPos+modelTag.length(), modelEndPos-modelStartPos-modelTag.length());
            }

            // Parse Commands
            std::string strControlGroup = strConfiguration.substr(controlGroupStartPos + controlGroupTag.length(), controlGroupEndPos - controlGroupStartPos - controlGroupTag.length());
            parseControlGroup(strControlGroup, d.m_vecFunctions, d.m_strID);

            vecDevices.push_back(d);
        }
        deviceTypeDisplayNamePos = nextDeviceTypeDisplayNamePos;
    }
    return 0;
}


const std::string ReadAuthorizationTokenFile()
{
    std::string strAuthorizationToken;
    std::ifstream AuthorizationTokenFileStream (HARMONY_HUB_AUTHORIZATION_TOKEN_FILENAME);
    if (!AuthorizationTokenFileStream.is_open())
    {
        return strAuthorizationToken;
    }

    getline (AuthorizationTokenFileStream,strAuthorizationToken);

    AuthorizationTokenFileStream.close();
    
    return strAuthorizationToken;
}


int WriteAuthorizationTokenFile(const std::string& strAuthorizationToken)
{
    std::ofstream AuthorizationTokenFileStream;
    AuthorizationTokenFileStream.open(HARMONY_HUB_AUTHORIZATION_TOKEN_FILENAME);
    if(!AuthorizationTokenFileStream.is_open())
    {
        return 1;
    }
    AuthorizationTokenFileStream << strAuthorizationToken;
    AuthorizationTokenFileStream.close();

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
        printf("        list_activities_raw\n");
        printf("        get_current_activity_id\n");
        printf("        get_current_activity_id_raw\n");
        printf("        start_activity [ID]\n");
        printf("        list_devices\n");
        printf("        list_devices_raw\n");
        printf("        list_commands\n");
        printf("        list_device_commands [deviceId]\n");
        printf("        list_device_commands_raw [deviceId]\n");
        printf("        issue_device_command [deviceId] [command]\n");
        printf("        get_config\n");
        printf("        get_config_raw\n");
        printf("\n");
        return 0;
    }

    std::string strUserEmail = argv[1];
    std::string strUserPassword = argv[2];
    std::string strHarmonyIP = argv[3];
	std::string strCommand;
    std::string strCommandParameterPrimary;
    std::string strCommandParameterSecondary;
    
    int harmonyPortNumber = HARMONY_COMMUNICATION_PORT;

    // User requested an action to be performed
    if(argc >= 5)
    {
        strCommand = argv[4];
    }
    if(argc>=6)
    {
        strCommandParameterPrimary = argv[5];
    }

    if(argc==7)
    {
        strCommandParameterSecondary = argv[6];
    }

    bool bQuietMode = false;

    if(strCommand.length())
    {
        if( strCommand.find("_raw") != std::string::npos)
        {
            bQuietMode = true;
        }
    }

    // Read the token
    std::string strAuthorizationToken = ReadAuthorizationTokenFile();

    //printf("\nLogin Authorization Token is: %s\n\n", strAuthorizationToken.c_str());

    bool bAuthorizationComplete = false;

    if(strAuthorizationToken.length() > 0)
    {
        csocket authorizationcsocket;
        if(connectToHarmony(strHarmonyIP, harmonyPortNumber, authorizationcsocket) == 1)
        {
            log("HARMONY COMMUNICATION LOGIN    : FAILURE", false);
            printf("ERROR : %s\n", errorString.c_str());
            return 1;
        }

        if(swapAuthorizationToken(&authorizationcsocket, strAuthorizationToken) == 0)
        {
            // Authorization Token found in the file worked.  
            // Bypass authorization through Logitech's servers.
            log("LOGITECH WEB SERVICE LOGIN     : BYPASSED", bQuietMode);

            bAuthorizationComplete = true;
        }
        
    }

    
    if(bAuthorizationComplete == false)
    {
        // Log into the Logitech Web Service to retrieve the login authorization token
        if(harmonyWebServiceLogin(strUserEmail, strUserPassword, strAuthorizationToken) == 1)
        {
            log("LOGITECH WEB SERVICE LOGIN     : FAILURE", false);
            printf("ERROR : %s\n", errorString.c_str());
            return 1;
        }
        log("LOGITECH WEB SERVICE LOGIN     : SUCCESS", bQuietMode);

        //printf("\nLogin Authorization Token is: %s\n\n", strAuthorizationToken.c_str());

        // Write the Authorization Token to an Authorization Token file to bypass this step
        // on future sessions
        WriteAuthorizationTokenFile(strAuthorizationToken);

        // Log into the harmony hub to convert the login authorization token for a 
        // session authorization token
    
        csocket authorizationcsocket;
        if(connectToHarmony(strHarmonyIP, harmonyPortNumber, authorizationcsocket) == 1)
        {
            log("HARMONY COMMUNICATION LOGIN    : FAILURE", false);
            printf("ERROR : %s\n", errorString.c_str());
            return 1;
        }


        if(swapAuthorizationToken(&authorizationcsocket, strAuthorizationToken) == 1)
        {
            log("HARMONY COMMUNICATION LOGIN    : FAILURE", false);
            printf("ERROR : %s\n", errorString.c_str());
            return 1;
        }
    }

    log("HARMONY COMMUNICATION LOGIN    : SUCCESS", bQuietMode);


    //printf("\nSession Authorization Token is: %s\n\n", strAuthorizationToken.c_str());

    // We've successfully obtained our session authorization token from the harmony hub 
    // using the login authorization token we received earlier from the Logitech web service.
    // Now, disconnect from the harmony and reconnect using the mangled session token 
    // as our username and password to issue a command.


    csocket commandcsocket;
    if(connectToHarmony(strHarmonyIP, harmonyPortNumber, commandcsocket) == 1)
    {
        log("HARMONY COMMAND SUBMISSION     : FAILURE", false);
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

    if(strCommand == "list_activities"              || 
        strCommand == "list_activities_raw"         || 
        strCommand == "list_devices"                || 
        strCommand == "list_devices_raw"            || 
        strCommand == "list_commands"               || 
        strCommand == "list_device_commands"        || 
        strCommand == "list_device_commands_raw"    || 
        strCommand == "get_config")
    {
        lstrCommand = "get_config_raw";
    }

    if(submitCommand(&commandcsocket, strAuthorizationToken, lstrCommand, strCommandParameterPrimary, strCommandParameterSecondary) == 1)
    {
        log("HARMONY COMMAND SUBMISSION     : FAILURE", false);
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }

    log("HARMONY COMMAND SUBMISSION     : SUCCESS", bQuietMode);
    
    if(lstrCommand == "get_config_raw")
    {
        std::map< std::string, std::string> mapActivities;
        std::vector< Device > vecDevices;
        if(parseConfiguration(resultString, mapActivities, vecDevices) == 1)
        {
            log("PARSE ACTIVITIES AND DEVICES   : FAILURE", false);
            printf("ERROR : %s\n", errorString.c_str());
            return 1;
        }

        if(strCommand == "list_activities" || strCommand == "list_activities_raw" )
        {
            resultString = "";

            if(strCommand == "list_activities")
            {
                resultString = "Activities Available via Harmony : \n\n";
            }
        
            std::map< std::string, std::string>::iterator it = mapActivities.begin();
            std::map< std::string, std::string>::iterator ite = mapActivities.end();
            for(; it != ite; ++it)
            {
                resultString.append(it->first);
                resultString.append(" - ");
                resultString.append(it->second);
                resultString.append("\n");

            }
        }

        if( strCommand == "list_devices" || strCommand == "list_devices_raw" )
        {
            resultString = "";
            
            if( strCommand == "list_devices" )
            {
                resultString = "Devices Controllable via Harmony : \n\n";
            }

            std::vector< Device >::iterator it = vecDevices.begin();
            std::vector< Device >::iterator ite = vecDevices.end();
            for(; it != ite; ++it)
            {
                resultString.append(it->m_strID );
                resultString.append(" - ");
                resultString.append(it->m_strLabel );
                resultString.append("\n");
                
            }
        }

        if(strCommand == "list_commands" || strCommand == "list_commands_raw" )
        {
            resultString = "";
            
            if(strCommand == "list_commands")
            {
                resultString = "Devices Controllable via Harmony with Commands : \n\n";
            }
            std::vector< Device >::iterator it = vecDevices.begin();
            std::vector< Device >::iterator ite = vecDevices.end();
            for(; it != ite; ++it)
            {
                resultString.append(it->toString());
                resultString.append("\n\n\n");
            }
        }

        if(strCommand == "list_device_commands" || strCommand == "list_device_commands_raw")
        {
            resultString = "";
            
            if(strCommand == "list_device_commands")
            {
                resultString = "Harmony Commands for Device: \n\n";
            }
            
            std::vector< Device >::iterator it = vecDevices.begin();
            std::vector< Device >::iterator ite = vecDevices.end();
            for(; it != ite; ++it)
            {
                if(it->m_strID == strCommandParameterPrimary)
                {
                    if(strCommandParameterSecondary.length())
                    {
                        if(strCommandParameterSecondary == it->m_strID)
                        {
                            resultString.append(it->toString());
                            resultString.append("\n\n\n");
                        }
                    }
                    else
                    {
                        resultString.append(it->toString());
                        resultString.append("\n\n\n");
                    }
                    

                    break;
                }
            }
        }
        log("PARSE ACTIVITIES AND DEVICES   : SUCCESS", bQuietMode);
    }

    printf("%s\n\n", resultString.c_str());

    return 0;
}

