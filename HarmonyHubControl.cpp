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
#include <QtWidgets>
#include <QtNetwork>

std::string errorString;
std::string resultString;

#define LOGITECH_AUTH_URL "https://svcs.myharmony.com/CompositeSecurityServices/Security.svc/json/GetUserAuthToken"
#define HARMONY_COMMUNICATION_PORT 5222
#define CONNECTION_ID "12345678-1234-5678-1234-123456789012-1"

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
    QByteArray jsonString = "{\"email\":\"";
    jsonString.append(strUserEmail.c_str());
    jsonString.append("\",\"password\":\"");
    jsonString.append(strPassword.c_str());
    jsonString.append("\"}");

    QByteArray postDataSize = QByteArray::number(jsonString.size());

    
    QUrl serviceURL(LOGITECH_AUTH_URL);
    QNetworkRequest request(serviceURL);
    
    request.setRawHeader("content-type", "application/json;charset=utf-8");
    request.setRawHeader("content-length", postDataSize);

    QNetworkAccessManager networkManager;

    // Post the request and wait for a reply synchronously
    QEventLoop eventLoop;
    eventLoop.connect(&networkManager, SIGNAL(finished(QNetworkReply*)), SLOT(quit()));

    QNetworkReply * reply = networkManager.post(request, jsonString);
    eventLoop.exec(QEventLoop::AllEvents|QEventLoop::WaitForMoreEvents);

    // Check for errors in the response
    if (reply->error() != QNetworkReply::NoError)
    {
        errorString = "harmonyWebServiceLogin : Error in reply from Logitech web service";
        return 1;  
    }

    // Read the response text
    std::string strResponseText = ((QString) reply->readAll()).toStdString();
    if(strResponseText.length() == 0)
    {
        errorString = "harmonyWebServiceLogin : Empty login response Logitech web service";
        return 1;  
    }
    
    // Parse the login authorization token from the response
    std::string strAuthTokenTag = "UserAuthToken\":\"";
    int pos = (int)strResponseText.find(strAuthTokenTag);
    if(pos == std::wstring::npos)
    {
        errorString = "harmonyWebServiceLogin : Logitech web service response does not contain a login authorization token";
        return 1;  
    }

    strAuthorizationToken = strResponseText.substr(pos + strAuthTokenTag.length());
    pos = (int)strAuthorizationToken.find("\"}}");
    strAuthorizationToken = strAuthorizationToken.substr(0, pos);

    // Remove forward slashes
    strAuthorizationToken.erase(std::remove(strAuthorizationToken.begin(), strAuthorizationToken.end(), '\\'), strAuthorizationToken.end());
    return 0;
}

int connectToHarmony(std::string strHarmonyIPAddress, int harmonyPortNumber, QTcpSocket& harmonyCommunicationSocket)
{
    if(strHarmonyIPAddress.length() == 0 || harmonyPortNumber == 0 || harmonyPortNumber > 65535)
    {
        errorString = "connectToHarmony : Empty Harmony IP Address or Port";
        return 1;
    }

    harmonyCommunicationSocket.connectToHost(strHarmonyIPAddress.c_str(), harmonyPortNumber);
    harmonyCommunicationSocket.waitForConnected();

    if (harmonyCommunicationSocket.state() != QAbstractSocket::ConnectedState)
    {
        errorString = "connectToHarmony : Unable to connect to specified IP Address on specified Port";
        return 1;
    }

    return 0;
}

int startCommunication(QTcpSocket* communicationSocket, std::string strUserName, std::string strPassword)
{
    if(communicationSocket == NULL || strUserName.length() == 0 || strPassword.length() == 0)
    {
        errorString = "startCommunication : Invalid communication parameter(s) provided";
        return 1;
    } 

    // Start communication
    QByteArray data = "<stream:stream to='connect.logitech.com' xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xml:lang='en' version='1.0'>";
    communicationSocket->write(data);
    communicationSocket->waitForBytesWritten(data.length());
    communicationSocket->waitForReadyRead();
    data = communicationSocket->readAll();

    std::string strData = ((QString) data).toStdString(); /* <- Expect: <?xml version='1.0' encoding='iso-8859-1'?><stream:stream from='' id='XXXXXXXX' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features> */

    data = "<auth xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\" mechanism=\"PLAIN\">";
    QByteArray tmp = QString('\0' + QString(strUserName.c_str()) + '\0' + QString(strPassword.c_str())).toUtf8();
    data.append(tmp.toBase64());
    data.append("</auth>");
    communicationSocket->write(data);
    communicationSocket->waitForBytesWritten(data.length());
    communicationSocket->flush();

    communicationSocket->waitForReadyRead();
    data = communicationSocket->readAll();
    communicationSocket->flush();

    strData = ((QString) data).toStdString(); /* <- Expect: <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/> */
    if(strData != "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
    {
        errorString = "startCommunication : connection error";
        return 1;
    } 

    data = "<stream:stream to='connect.logitech.com' xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xml:lang='en' version='1.0'>";
    communicationSocket->write(data);
    communicationSocket->waitForBytesWritten(data.length());
    communicationSocket->waitForReadyRead();
    data = communicationSocket->readAll();

    strData = ((QString) data).toStdString(); /* <- Expect: <?xml version='1.0' encoding='iso-8859-1'?><stream:stream from='' id='057a30bd' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features> */

    return 0;
}

int swapAuthorizationToken(QTcpSocket* authorizationSocket, std::string& strAuthorizationToken)
{
    if(authorizationSocket == NULL || strAuthorizationToken.length() == 0)
    {
        errorString = "swapAuthorizationToken : NULL socket or empty authorization token provided";
        return 1;
    }

    if(startCommunication(authorizationSocket, "guest", "gatorade.") != 0)
    {
        errorString = "swapAuthorizationToken : Communication failure";
        return 1;
    }

    std::string strData;
    QByteArray sendData;
    QByteArray recvData;

    // GENERATE A LOGIN ID REQUEST USING THE HARMONY ID AND LOGIN AUTHORIZATION TOKEN 
    sendData = "<iq type=\"get\" id=\"";
    sendData.append(CONNECTION_ID);
    sendData.append("\"><oa xmlns=\"connect.logitech.com\" mime=\"vnd.logitech.connect/vnd.logitech.pair\">token=");
    sendData.append(strAuthorizationToken.c_str());
    sendData.append(":name=foo#iOS6.0.1#iPhone</oa></iq>");

    std::string strIdentityTokenTag = "identity=";
    int pos = std::wstring::npos;
    
    authorizationSocket->write(sendData);
    authorizationSocket->waitForBytesWritten(sendData.length());
    
    authorizationSocket->waitForReadyRead();
    recvData = authorizationSocket->readAll();
    authorizationSocket->flush();
        
    strData = ((QString) recvData).toStdString(); /* <- Expect: <iq/> */

    if(strData != "<iq/>")
    {
        errorString = "swapAuthorizationToken : Invalid Harmony response";
        return 1;  
    }

    authorizationSocket->waitForReadyRead();
    recvData = authorizationSocket->readAll();
    authorizationSocket->flush();

                                                                                                
    strData = ((QString) recvData).toStdString(); /* <- Expect: <success xmlns= ... identity=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:status=succeeded ... */

    // Parse the session authorization token from the response
    pos = (int)strData.find(strIdentityTokenTag);
    if(pos == std::wstring::npos)
    {
        errorString = "swapAuthorizationToken : Logitech Harmony response does not contain a session authorization token";
        return 1;  
    }
    
    strAuthorizationToken = strData.substr(pos + strIdentityTokenTag.length());

    pos = (int)strAuthorizationToken.find(":status=succeeded");
    if(pos == std::wstring::npos)
    {
        errorString = "swapAuthorizationToken : Logitech Harmony response does not contain a valid session authorization token";
        return 1;  
    }
    strAuthorizationToken = strAuthorizationToken.substr(0, pos);

    return 0;
}


int submitCommand(QTcpSocket* commandSocket, std::string& strAuthorizationToken, std::string strCommand, std::string strCommandParameter)
{
    if(commandSocket== NULL || strAuthorizationToken.length() == 0)
    {
        errorString = "submitCommand : NULL socket or empty authorization token provided";
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

    QByteArray sendData;
    QByteArray recvData;

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
        // Actions are of the form:
        //     <iq type="get" id="5e518d07-bcc2-4634-ba3d-c20f338d8927-2">
        //         <oa xmlns="connect.logitech.com" mime="vnd.logitech.harmony/vnd.logitech.harmony.engine?holdAction">
        //             action={"type"::"IRCommand","deviceId"::"11586428","command"::"VolumeDown"}:status=press
        //         </oa>
        //     </iq>

    }

    commandSocket->write(sendData);
    commandSocket->waitForBytesWritten(sendData.length());

    commandSocket->waitForReadyRead();
    recvData = commandSocket->readAll();
    while(commandSocket->bytesAvailable())
    {
        recvData.append(commandSocket->readAll());
        commandSocket->flush();
    };


    strData = ((QString) recvData).toStdString(); /* <- Expect: <iq/> */

    
    std::string iqTag = "<iq/>";
    int pos = (int)strData.find(iqTag);

    if(pos != 0)
    {
        errorString = "submitCommand: Invalid Harmony response";
        return 1;  
    }

    commandSocket->waitForReadyRead();
    recvData = commandSocket->readAll();
    while(commandSocket->bytesAvailable())
    {
        recvData.append(commandSocket->readAll());
        commandSocket->flush();
    };
    
    strData = ((QString) recvData).toStdString(); 
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
        int recvDataPrevLength = 0;
        recvData.clear();
        do{
            recvDataPrevLength = recvData.length();
            commandSocket->waitForReadyRead(1000);
            recvData.append(commandSocket->readAll());
            commandSocket->flush();
        }while(recvData.length() != recvDataPrevLength);

        strData.append(((QString) recvData).toStdString()); 

        pos = strData.find("![CDATA[{");
        if(pos != std::string::npos)
        {
            resultString = "Logitech Harmony Configuration : \n" + strData.substr(pos + 9);
        }
    }
    else if (strCommand == "start_activity")
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
    QApplication a(argc, argv);

    if (argc < 4)
    {
        printf("Syntax:\n");
        printf("HarmonyHubControl.exe [email] [password] [harmony_ip] [command (optional)]\n");
        printf("    where command can be any of the following:\n");
        printf("        list_activities\n");
        printf("        get_current_activity_id\n");
        printf("        start_activity [ID]\n");
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
    int harmonyPortNumber = HARMONY_COMMUNICATION_PORT;

    // User requested an action to be performed
    if(argc >= 5)
    {
        strCommand = argv[4];
    }
    if(argc==6)
    {
        strCommandParameter = argv[5];
    }

    QNetworkProxyFactory::setUseSystemConfiguration(true);

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

    QTcpSocket authorizationSocket;
    if(connectToHarmony(strHarmonyIP, harmonyPortNumber, authorizationSocket) == 1)
    {
        printf("FAILURE\n");
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }

    if(swapAuthorizationToken(&authorizationSocket, strAuthorizationToken) == 1)
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

    authorizationSocket.close();

    printf("HARMONY COMMAND SUBMISSION     : ");

    QTcpSocket commandSocket;
    if(connectToHarmony(strHarmonyIP, harmonyPortNumber, commandSocket) == 1)
    {
        printf("FAILURE\n");
        printf("ERROR : %s\n", errorString.c_str());
        return 1;
    }

    std::string strUserName = strAuthorizationToken;
    //strUserName.append("@connect.logitech.com/gatorade.");
    std::string strPassword = strAuthorizationToken;
    
    if(startCommunication(&commandSocket, strUserName, strPassword) == 1)
    {
        errorString = "Communication failure";
        return 1;
    }

    std::string lstrCommand = strCommand;

    if(strCommand == "list_activities" || strCommand == "list_devices")
    {
        lstrCommand = "get_config";
    }

    if(submitCommand(&commandSocket, strAuthorizationToken, lstrCommand, strCommandParameter) == 1)
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