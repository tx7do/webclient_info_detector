<?php

ini_set('display_errors', 'On');
error_reporting(E_ALL);
include dirname(__FILE__) . '/useragent.class.php';

/**
 * 获取客户端IP地址
 * @param integer $type 返回类型 0 返回IP地址 1 返回IPV4地址数字
 * @param boolean $adv 是否进行高级模式获取（有可能被伪装） 
 * @return mixed
 */
function get_ip($type = 0, $adv = true)
{
	$type = $type ? 1 : 0;
	static $ip = NULL;
	if ($ip !== NULL) return $ip[$type];
	if ($adv)
	{
		if (isset($_SERVER['HTTP_X_FORAORDED_FOR']))
		{
			$ip = $_SERVER['HTTP_X_FORAORDED_FOR'];
		}
		elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
		{
			$arr = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
			$pos = array_search('unknown', $arr);
			if (false !== $pos) unset($arr[$pos]);
			$ip = trim($arr[0]);
		}
		elseif (isset($_SERVER['HTTP_CLIENT_IP']))
		{
			$ip = $_SERVER['HTTP_CLIENT_IP'];
		}
		elseif (isset($_SERVER['REMOTE_ADDR']))
		{
			$ip = $_SERVER['REMOTE_ADDR'];
		}
	}
	elseif (isset($_SERVER['REMOTE_ADDR']))
	{
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	// IP地址合法验证
	$long = sprintf("%u", ip2long($ip));
	$ip = $long ? array($ip, $long) : array('0.0.0.0', 0);
	return $ip[$type];
}

/// 检查代理
function proxy_detect()
{
	$sockport = false;
	$proxyports = array(80,8080,6588,8000,3128,3127,3124,1080,553,554);
	for ($i = 0; $i <= count($proxyports); $i++)
	{
		if(@fsockopen($_SERVER['REMOTE_ADDR'],$proxyports[$i],$errstr,$errno,0.5))
		{
			$sockport=true;
		}
	}
	if (
		isset($_SERVER['HTTP_FORAORDED'])
		|| isset($_SERVER['HTTP_X_FORAORDED_FOR'])
		|| isset($_SERVER['HTTP_CLIENT_IP'])
		|| isset($_SERVER['HTTP_VIA'])
		|| isset($_SERVER['HTTP_XROXY_CONNECTION'])
		|| isset($_SERVER['HTTP_PROXY_CONNECTION'])
		|| $sockport == true
	)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/// 检查代理
function proxy_detect_ex()
{
	$proxy_headers = array(
        'HTTP_VIA',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_FORWARDED',
        'HTTP_CLIENT_IP',
        'HTTP_FORWARDED_FOR_IP',
        'VIA',
        'X_FORWARDED_FOR',
        'FORWARDED_FOR',
        'X_FORWARDED',
        'FORWARDED',
        'CLIENT_IP',
        'FORWARDED_FOR_IP',
        'HTTP_PROXY_CONNECTION'
    );
    foreach($proxy_headers as $x)
    {
        if (isset($_SERVER[$x])) return true;
    }
    return false;
}

/// 生成随机码
function generate_code()
{
	return strtoupper(substr(md5(microtime(true)), 0, 6));
}

/// 返回json数据
function response_data($code, $ip, $use_proxy)
{
	$data = array(
		'code' => $code,
		'proxyType' => $use_proxy == true ? 2 : 1,
		'ip'=> $ip);
	echo json_encode($data);
}

/// 保存文件
function save_file($code, $data)
{
	$filedir = 'data';
	if (!is_dir($filedir))
	{
		mkdir($filedir);
	}

	$filename = $code . ".html";
	$fp = fopen("$filedir/$filename", "w");
	fwrite($fp, $data);
	fclose($fp);
}

function make_fake_json()
{
	$_data =
<<<data
{
    "FlashVersion":"0.0.0",
    "UserAgent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.23 Safari/537.36",
    "Platform":"Win32",
    "OsVersion":"Windows NT 10.0",
    "BrowserName":"Chrome",
    "BrowserVersion":"69.0.3497.23",
    "UbDataVersion":"none",
    "IE":"Not IE",
    "CookieEnable":true,
    "JavaEnable":false,
    "ScreenWidth":1920,
    "ScreenHeight":1080,
    "Timestamp":1534075831,
    "Referer":"http://localhost:8082/check/",
    "advanced":{
        "PluginNames":[
            "Chrome PDF Plugin",
            "Chrome PDF Viewer",
            "Native Client"
        ]
    }
}
data;
	return ($_data);
}

function make_html($code, $ip, $use_proxy, $json_data, $user_agent)
{
	$BrowserName = $user_agent->browser['title'];
	$OsName = $user_agent->os['title'];
	$DeviceType = $user_agent->platform['type'] == 'os' ? 'PC' : '移动设备';
	$DeviceName = $user_agent->platform['type'] == 'os' ? 'PC' : $user_agent->device['title'];
	$_data =
<<<data
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>$code</title>
</head>
<body>
<table border="1">
<tr>
	<th>编号</th>
	<th>客户端ip</th>
	<th>是否使用代理</th>
	<th>屏幕大小</th>
	<th>浏览器</th>
	<th>操作系统</th>
	<th>设备类型</th>
	<th>设备名</th>
	<th>Flash版本</th>
	<th>User-Agent</th>
</tr>
<tr>
	<td>$code</td>
	<td>$ip</td>
	<td>$use_proxy</td>
	<td>$json_data->ScreenWidth * $json_data->ScreenHeight</td>
	<td>$BrowserName</td>
	<td>$OsName</td>
	<td>$DeviceType</td>
	<td>$DeviceName</td>
	<td>$json_data->FlashVersion</td>
	<td>$user_agent->useragent</td>
</tr>
</table>
</body>
</html>
data;
	return $_data;
}

/// 执行检测
function check()
{
	$code = generate_code();
	$ip = get_ip();
	$use_proxy = proxy_detect();

	$postData = isset($_POST['Json']) ? $_POST['Json'] : make_fake_json();
	$jsonData = isset($postData) ? json_decode($postData) : null;

	//$useragent = UserAgentFactory::analyze($_SERVER['HTTP_USER_AGENT']);
	$useragent = UserAgentFactory::analyze($jsonData->UserAgent);
	//var_dump($useragent);
	
	$html_data = make_html($code, $ip, $use_proxy ? '是' : '否', $jsonData, $useragent);
	save_file($code, $html_data);

	response_data($code, $ip, $use_proxy);
}
check();
