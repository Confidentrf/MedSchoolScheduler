<?PHP
/**
* squidgLogic.php
* 
* @author James Logwood
* @author jvlogwood@liberty.edu
* 
* @version 0.1
* 
* This is a simple front end tool that makes it easier to use existing APIs
* 
* Dependencies: Klogger, adLDAP, /var/core/config/config.ini (file)
*
**/

require_once('/var/core/classes/logging/KLogger.php');
require_once('/var/core/classes/adLDAP/adLDAP.php');
//require_once('/var/core/classes/curl/2.0/CurlyCrutchV2.php');

$date = new DateTime(NULL,new DateTimeZone("UTC"));
$logger = new KLogger ("logs/squidgLogic_" . $date->format("Y-m-d") . ".log", KLogger::DEBUG);

/*
*
* Checkes to make sure that the $form param is present
*
*/
if(empty($_POST['form']))
{
	$error =  "Missing the param $form";
	$logger->LogError($error);
	header("HTTP/1.0 400 Bad Request");
	echo '{"error":"' . $error . '"}';
	exit();
}

/*
*
* Large If block for each individual handler
*
*/

/*
*
* Already Logged in handler
*
*/
if(strtoupper(trim($_POST['form'])) == "LOGGEDIN")
{
	session_start();
	if(empty($_SESSION['username'])){
		header("HTTP/1.0 401 Unauthorised");
		exit();
	}
}

/*
*
* Logout handler
*
*/
if(strtoupper(trim($_POST['form'])) == "LOGOUT")
{
	/*
	*
	* This code was pretty much stolen from the user Pekka on StackOverflow, beacuse I'm lazy. 
	* http://stackoverflow.com/questions/3948230/best-way-to-completely-destroy-a-session-even-if-the-browser-is-not-closed
	*
	*/
	session_start();
	$logger->LogDebug("Preparing to logout the user " . $_SESSION['username']);
	
	$_SESSION = array();
	if (ini_get("session.use_cookies")) {
		$params = session_get_cookie_params();
		setcookie(session_name(), '', time() - 42000,
			$params["path"], $params["domain"],
			$params["secure"], $params["httponly"]
		);
	}
	session_destroy();
	exit();
}

/*
*
* Login form logic
*
*/
if(strtoupper(trim($_POST['form'])) == "LOGINFORM")
{
	/*
	*
	* Checks for necessary paramaters
	*
	*/
	if(empty($_POST['password']) || empty($_POST['username']))
	{
		$error = "Please enter both a username and password";
		$logger->LogError($error);
		header("HTTP/1.0 400 Bad Request");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	
	/*
	*
	* Tries to build the needed adLDAP object
	*
	*/
	try{
		$adLDAP = new adLDAP(array("account_suffix"=>"@liberty.edu","base_dn"=>"DC=University,DC=liberty,DC=edu","domain_controllers"=>array("university.liberty.edu"),"admin_username"=>"lecturecapture","admin_password"=>"k6RAHpi63SIVbmY8"));
	} catch (Exception $e){
		$error = "An exception was thrown while creating the adLDAP object. The exception is: " . var_export($e);
		$logger->LogError($error);
		header("HTTP/1.0 500 Internal Server Error");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	
	$username = trim($_POST['username']);
	$password = trim ($_POST['password']);
	
	/*
	*
	* This handels the case where we are unable to authenticate the user
	*
	*/
	$user = $adLDAP->authenticate($username,$password);
	if (!$user)
	{
		$error = "Invalid username/password combination";
		$logger->LogError($error);
		header("HTTP/1.0 401 Unauthorised");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	
	/*
	*
	* This checks to make sure that the user is in the appropriate AD group
	*
	*/
	$group = $adLDAP->user()->inGroup($username, 'Staff');
	if(!$group)
	{
		$error = "Access Denied";
		$logger->LogError($error);
		header("HTTP/1.0 403 Forbidden");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	
	$logger->LogInfo("The user $username is authorized to access this application. Preparing to start a session.");
	
	/*
	*
	* Attempts to start a session on the server and add the username to the session if successful the script returns a 
	* 200 OK header, closes the AD connection, and exits
	*
	*/
	$session = session_start();
	if(!$session){
		$error = "Failed to start a PHP session.";
		$logger->LogError($error);
		header("HTTP/1.0 500 Internal Server Error");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	$logger->LogInfo("Session started successfully");
	$_SESSION['username'] = $username;
	header("HTTP/1.0 200 OK");
	$adLDAP->close();
	exit();
} 

/*
*
* Scheduler form logic
*
*/
else if (strtoupper(trim($_POST['form'])) == "SCHEDULERFORM")
{
	/*
	*
	* Check for a valid session
	*
	*/
	$session = session_start();
	if(!$session){
		$error = "Failed to start a PHP session.";
		$logger->LogError($error);
		header("HTTP/1.0 500 Internal Server Error");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	$logger->LogInfo("Session started successfully");
	
	if(empty($_SESSION['username'])){
		$error = "Unauthorised Access. No session data present.";
		$logger->LogError($error);
		header("HTTP/1.0 403 Forbidden");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	$logger->LogInfo("Session data present. Allowing the processing of the form.");
	
	/*
	*
	* Checks to make sure all required params are present
	*
	*/
	$reqParams = array(
				"organizer"=>'',
				"subject"=>'',
				"startTime"=>'',
				"endTime"=>'',
				"location"=>'',
				"school"=>'',
				"classNumber"=>'',
				"classSection"=>'',
				"classTerm"=>''#,
				#"publishDelay"=>'',
				#"retentionPeriod"=>''
				);
	$result = array_diff_key($reqParams,$_POST);
	if (count($result) > 0 )
	{
		$error = "Missing the required paramater(s): " . implode(",",$result);
		$logger->LogError($error);
		header("HTTP/1.0 400 Bad Request");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	
	/*
	*
	* Checks to make sure all required params are set
	*
	*/
	foreach($reqParams as $key => $value)
	{
		$logger->LogDebug("Currently evaluating the key: $key and the value: " . $_POST[$key]);
		if ($_POST[$key] == "")
		{
			$error = "The value for $key cannot be an empty string.";
			$logger->LogError($error);
			header("HTTP/1.0 400 Bad Request");
			echo '{"error":"' . $error . '"}';
			exit();
		}
	}

	$logger->LogDebug("Request has all the required paramaters");
	
	$startTime = new DateTime(trim($_POST['startTime']),new DateTimeZone("EST"));
	$endTime = new DateTime(trim($_POST['endTime']),new DateTimeZone("EST"));
	
	/*
	*
	* Makes sure the date isn't in the past
	*
	*/
	if($date->getTimestamp() > $startTime->getTimestamp() || $date->getTimestamp() > $endTime->getTimestamp())
	{
		$error = "The start/end time cannot be in the past";
			$logger->LogError($error);
			header("HTTP/1.0 500 Internal Server Error ");
			echo '{"error":"' . $error . '"}';
			exit();
	}
	
	/*
	*
	* Makes sure the end date isn't before the start date
	*
	*/
	if($startTime->getTimestamp() > $endTime->getTimestamp())
	{
		$error = "The end time cannot be before the start time";
			$logger->LogError($error);
			header("HTTP/1.0 500 Internal Server Error");
			echo '{"error":"' . $error . '"}';
			exit();
	}
	
	$startTime->setTimezone(new DateTimeZone("UTC"));
	$endTime->setTimezone(new DateTimeZone("UTC"));
	$logger->LogDebug("Successfully converted the times to UTC. Here are their values.\r\nStartTime: " . $startTime->format('Y-m-d H:i:s') . "\r\nEndTime: " . $endTime->format('Y-m-d H:i:s'));
	
	$startTime 	= $startTime->format('Y-m-d') . 'T' . $startTime->format('H:i:s') . 'Z';
	$endTime 	= $endTime  ->format('Y-m-d') . 'T' . $endTime  ->format('H:i:s') . 'Z';

	$logger->LogDebug("Converted dates... StartTime: $startTime  EndTime: $endTime");

	/*
	*
	* Curl data to server for processing
	*
	*/
	
	$jsonData = array(
		'@record'=>false,
		'@webex'=>false,
		'@live'=>false,
		'@spark'=>false,
		'GUID'=>null,
		'organizer' 	=>$_POST['organizer'],
		'subject'		=>$_POST['subject'],
		'startUTC'		=>$startTime,
		'endUTC'		=>$endTime,
		'location'		=>$_POST['location'],
		'attachments'	=>false,
		'metadata'		=>array(
				'School (Banner school code):' 			=>$_POST['school'],
				'Class Name (Banner name):'				=>$_POST['className'],
				'Class Number (Banner number):'			=>$_POST['classNumber'],
				'Class Section (Banner section):'		=>$_POST['classSection'],
				'Class Term (Banner term):'				=>$_POST['classTerm'],
				'Professor Name:'						=>$_POST['profName'],
				'Recording Definition (SD, HD, 2HD):'	=>'HD',
				'Guest Lecturer (optional):'			=>$_POST['guestLec'],
				'Publishing Delay (hours):'				=>$_POST['publishDelay'],
				'Key Terms\\/Tags (comma separated list):'				=>$_POST['keyTerms'],
				'Alternate Title (used to override generated title):'	=>'',
				'Retention Period (months):'			=>$_POST['retentionPeriod'],
			)
		);

	$jsonData = json_encode($jsonData);
	
	$ch = curl_init();
	curl_setopt($ch,CURLOPT_URL,'http://trogdor.phones.liberty.edu/api/scheduler/v1/newHandler.php');
	curl_setopt($ch,CURLOPT_POSTFIELDS,$jsonData);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
	curl_setopt($ch,CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'Content-Length: ' . strlen($jsonData)));
	$curlResponse = curl_exec($ch);
	$curlStatus = curl_getinfo($ch);
	curl_close($ch);
	
	$logger->LogDebug("Curl Status: \n" . var_export($curlStatus,true) . "\nCurl Response: \n" . var_export($curlResponse,true));
	
	if($curlStatus['http_code'] >= 300)
	{
		header("HTTP/1.0 " . $curlResponse['http_code']);
		echo '{"error":"A Serious error was encountered. Please check the logs on lulcs01 for more details."}';
	} 
	else if ($curlStatus['http_code'] >= 200 )
	{
		if ($curlStatus['http_code'] == 206 )
		{
			header("HTTP/1.0 202 Accepted");
			echo '{"message":"Created the event except for the SQL"}';
		}
		else if ($curlStatus['http_code'] == 204)
		{
			header("HTTP/1.0 202 Accepted");
			echo '{"message":"Umm... I\'m not sure what happened. somehow you got back the weird 204 header response"}';
		}
		else 
		{
			$curlResponse = str_replace("'","",$curlResponse);
			$logger->LogDebug("after str_replace" . $curlResponse);
			$curlResponse = json_decode($curlResponse,true);
			$logger->LogDebug("after json_decode" . var_export($curlResponse,true));
			header("HTTP/1.0 201 Created");
			echo '{"message":"Here is the GUID ' . $curlResponse['guid'] .'"}';
		}
	}
}

/*
*
* KalturaEntryUpdaterForm form logic
*
*/

else if (strtoupper(trim($_POST['form'])) == "KALTURAENTRYUPDATERFORM")
{
	/*
	*
	* Check for a valid session
	*
	*/
	$session = session_start();
	if(!$session){
		$error = "Failed to start a PHP session.";
		$logger->LogError($error);
		header("HTTP/1.0 500 Internal Server Error");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	$logger->LogInfo("Session started successfully");
	
	if(empty($_SESSION['username'])){
		$error = "Unauthorised Access. No session data present.";
		$logger->LogError($error);
		header("HTTP/1.0 403 Forbidden");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	$logger->LogInfo("Session data present. Allowing the processing of the form.");
	
	/*
	*
	* Check for required paramaters
	*
	*/
	
	if(empty($_POST['kalturaEntryUpdater_entryID']) || empty($_POST['kalturaEntryUpdater_GUID']))
	{
		$error = "Please enter both an entryID and GUID";
		$logger->LogError($error);
		header("HTTP/1.0 400 Bad Request");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	$logger->LogInfo("All required paramaters are present");
	
	/*
	*
	* Checks to make sure the guid is actually a GUID
	*
	*/
	
	$logger->LogInfo("Checking the POST value for the GUID: {$_POST['kalturaEntryUpdater_GUID']}");
	
	$guid = strtoupper(trim($_POST['kalturaEntryUpdater_GUID']));
	$isGuid = preg_match('/^\{?[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\}?$/', $guid);
	
	if($isGuid === 0 || $isGuid === false)
	{
		$error = "GUID supplied is not a valid GUID";
		$logger->LogError($error);
		header("HTTP/1.0 500 Internal Server Error");
		echo '{"error":"' . $error . '"}';
		exit();
	}
	
	// Throwing Jason a bone here...
	$logger->LogInfo("GUID is a valid GUID. . . because it's complex");
	
	/*
	*
	* cURLing the Data
	*
	*/
	$entryid = trim($_POST['kalturaEntryUpdater_entryID']);
	
	$logger->LogInfo("Preparing to cURL");
	$ch = curl_init();
	curl_setopt($ch,CURLOPT_URL,"http://127.0.0.1/api/kaltura/entryUpdater/v2.0/kalturaEntryUpdater.php?guid=$guid&entryid=$entryid");
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
	$curlResponse = curl_exec($ch);
	$curlStatus = curl_getinfo($ch);
	curl_close($ch);
	$logger->LogDebug("Curl Status: " . var_export($curlStatus,true));
	$logger->LogDebug("Curl Response: " . var_export($curlResponse,true));
	/*
	*
	* Check the response back 
	*
	*/
	
	if($curlStatus['http_code'] >= 300)
	{
		header("HTTP/1.0 " . $curlStatus['http_code']);
		echo '{"error":"A Serious error was encountered. Please check the logs for more details."}';
	} 
	else if ($curlStatus['http_code'] >= 200 )
	{
		if ($curlStatus['http_code'] == 206 )
		{
			header("HTTP/1.0 202 Accepted");
			echo '{"message":"Updated the entry but there was a non-fatal error"}';
		} 
		else 
		{
			$json = json_decode($curlResponse['data'],true);
			header("HTTP/1.0 202 Created");
			echo '{"message":"Entry has been updated"}';
		}
	}
}



?>
